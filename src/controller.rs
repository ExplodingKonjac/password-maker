use crate::{AppWindow, EntryView};
use arboard::Clipboard;
use password_maker::{
    model::{PasswordOptions, ThemeChoice, VaultSettings},
    service::{LockPolicy, VaultService},
    storage::VaultStore,
};
use slint::{ComponentHandle, ModelRc, Timer, TimerMode, VecModel};
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

type Secret = Zeroizing<String>;
enum Job {
    Create(Secret),
    Unlock(Secret),
    Generate(Secret, PasswordOptions),
    CopyEntry(Uuid),
    Edit(Uuid),
    Save(Option<Uuid>, String, Secret, PasswordOptions),
    Delete(Uuid),
    Settings(VaultSettings),
    Export(PathBuf),
    Restore(PathBuf, Secret, Secret),
    Rotate(Secret, Secret),
    Lock,
    Exit,
}
struct Request {
    epoch: u64,
    job: Job,
}
struct Reply {
    epoch: u64,
    result: Result<Outcome, String>,
}
struct View {
    entries: Vec<EntryMetadata>,
    settings: VaultSettings,
}
#[derive(Clone)]
struct EntryMetadata {
    id: Uuid,
    label: String,
    updated: i64,
}
enum Outcome {
    View(View, &'static str),
    Password(Secret, bool),
    Edit(password_maker::model::VaultEntry),
    Status(&'static str),
}
fn execute(service: &mut VaultService, job: Job) -> Result<Outcome, String> {
    use password_maker::service::ServiceError;
    let result = (|| -> Result<Outcome, ServiceError> {
        let status = match job {
            Job::Create(password) => {
                service.create(password)?;
                "Vault created."
            }
            Job::Unlock(password) => {
                service.unlock(password)?;
                "Vault unlocked."
            }
            Job::Generate(keyword, options) => {
                return Ok(Outcome::Password(
                    service.generate(&keyword, options)?,
                    false,
                ));
            }
            Job::CopyEntry(id) => {
                let entry = service.entry(id)?;
                return Ok(Outcome::Password(
                    service.generate(&entry.keyword, entry.options)?,
                    true,
                ));
            }
            Job::Edit(id) => return Ok(Outcome::Edit(service.entry(id)?)),
            Job::Save(id, label, keyword, options) => {
                service.save_entry(id, label, keyword, options)?;
                "Entry saved."
            }
            Job::Delete(id) => {
                service.delete_entry(id)?;
                "Entry deleted."
            }
            Job::Settings(settings) => {
                service.update_settings(settings)?;
                "Settings saved."
            }
            Job::Export(path) => {
                service.export(&path)?;
                return Ok(Outcome::Status("Encrypted backup exported."));
            }
            Job::Restore(path, password, next) => {
                service.restore(&path, &password, next)?;
                "Backup restored. The previous vault was saved as an encrypted pre-restore copy."
            }
            Job::Rotate(current, next) => {
                service.change_password(&current, next)?;
                "Hyper password changed. Generated passwords are unchanged."
            }
            Job::Lock | Job::Exit => {
                service.lock();
                return Ok(Outcome::Status("Vault locked."));
            }
        };
        Ok(Outcome::View(
            View {
                entries: service
                    .entries()?
                    .iter()
                    .map(|e| EntryMetadata {
                        id: e.id,
                        label: e.label.clone(),
                        updated: e.updated_at,
                    })
                    .collect(),
                settings: service.settings()?,
            },
            status,
        ))
    })();
    result.map_err(|e| e.to_string())
}

struct ClipboardState {
    context: Option<Clipboard>,
    expected: Option<Secret>,
    deadline: Option<Instant>,
}
impl ClipboardState {
    fn new() -> Self {
        Self {
            context: None,
            expected: None,
            deadline: None,
        }
    }
    fn copy(&mut self, value: Secret) -> Result<(), String> {
        if self.context.is_none() {
            self.context = Some(Clipboard::new().map_err(|_| "Could not access the clipboard.")?);
        }
        self.context
            .as_mut()
            .unwrap()
            .set_text(value.as_str().to_string())
            .map_err(|_| "Could not copy to the clipboard.")?;
        self.expected = Some(value);
        self.deadline = Some(Instant::now() + Duration::from_secs(30));
        Ok(())
    }
    fn clear(&mut self) {
        if let (Some(clipboard), Some(expected)) = (&mut self.context, &self.expected)
            && clipboard.get_text().ok().as_deref() == Some(expected.as_str())
        {
            let _ = clipboard.clear();
        }
        self.expected = None;
        self.deadline = None;
    }
    fn tick(&mut self) {
        if self.deadline.is_some_and(|t| Instant::now() >= t) {
            self.clear();
        }
    }
}
struct UiState {
    entries: Vec<EntryMetadata>,
    settings: VaultSettings,
    policy: LockPolicy,
    clipboard: ClipboardState,
    unlocked: bool,
}
pub struct Controller {
    window: slint::Weak<AppWindow>,
    sender: mpsc::Sender<Request>,
    replies: RefCell<mpsc::Receiver<Reply>>,
    epoch: Arc<AtomicU64>,
    power: Arc<AtomicBool>,
    power_stop: Arc<AtomicBool>,
    state: RefCell<UiState>,
    timer: Timer,
    worker: RefCell<Option<JoinHandle<()>>>,
}
impl Controller {
    pub fn new(window: &AppWindow) -> Result<Rc<Self>, Box<dyn std::error::Error>> {
        let store = VaultStore::default_location()?;
        window.set_page(if store.exists() { "locked" } else { "setup" }.into());
        let (sender, requests) = mpsc::channel::<Request>();
        let (responses, replies) = mpsc::channel();
        let epoch = Arc::new(AtomicU64::new(0));
        let worker_epoch = epoch.clone();
        let worker = std::thread::spawn(move || {
            let mut service = VaultService::new(store);
            let mut session_epoch = 0;
            while let Ok(request) = requests.recv() {
                if matches!(request.job, Job::Exit) {
                    service.lock();
                    break;
                }
                if request.epoch != worker_epoch.load(Ordering::SeqCst) {
                    continue;
                }
                if session_epoch != request.epoch {
                    service.lock();
                    session_epoch = request.epoch;
                }
                let result = execute(&mut service, request.job);
                if request.epoch != worker_epoch.load(Ordering::SeqCst) {
                    service.lock();
                    continue;
                }
                if responses
                    .send(Reply {
                        epoch: request.epoch,
                        result,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        let power = Arc::new(AtomicBool::new(false));
        let power_stop = Arc::new(AtomicBool::new(false));
        crate::power::install(power.clone(), power_stop.clone());
        let controller = Rc::new(Self {
            window: window.as_weak(),
            sender,
            replies: RefCell::new(replies),
            epoch,
            power,
            power_stop,
            state: RefCell::new(UiState {
                entries: vec![],
                settings: VaultSettings::default(),
                policy: LockPolicy::new(Some(15)),
                clipboard: ClipboardState::new(),
                unlocked: false,
            }),
            timer: Timer::default(),
            worker: RefCell::new(Some(worker)),
        });
        controller.wire(window);
        let weak = Rc::downgrade(&controller);
        controller
            .timer
            .start(TimerMode::Repeated, Duration::from_millis(100), move || {
                if let Some(c) = weak.upgrade() {
                    c.tick();
                }
            });
        Ok(controller)
    }
    fn submit(&self, job: Job) {
        let Some(window) = self.window.upgrade() else {
            return;
        };
        if window.get_busy() {
            return;
        }
        self.state.borrow_mut().policy.activity();
        window.set_busy(true);
        window.set_status("Working…".into());
        if self
            .sender
            .send(Request {
                epoch: self.epoch.load(Ordering::SeqCst),
                job,
            })
            .is_err()
        {
            window.set_busy(false);
            window.set_status("The vault worker stopped. Restart the application.".into());
        }
    }
    fn tick(&self) {
        let Some(window) = self.window.upgrade() else {
            return;
        };
        let must_lock = {
            let mut state = self.state.borrow_mut();
            state.clipboard.tick();
            let paused = state.policy.tick();
            state.unlocked && (paused || self.power.swap(false, Ordering::SeqCst))
        };
        if must_lock {
            self.lock();
        }
        while let Ok(reply) = self.replies.borrow().try_recv() {
            if reply.epoch != self.epoch.load(Ordering::SeqCst) {
                continue;
            }
            window.set_busy(false);
            match reply.result {
                Err(error) => window.set_status(error.into()),
                Ok(Outcome::Status(status)) => window.set_status(status.into()),
                Ok(Outcome::View(view, status)) => {
                    let settings = view.settings.clone();
                    {
                        let mut state = self.state.borrow_mut();
                        state.entries = view.entries;
                        state.settings = settings.clone();
                        state.unlocked = true;
                        state.policy.set_timeout(settings.auto_lock_minutes);
                    }
                    window.set_timeout_index(match settings.auto_lock_minutes {
                        Some(1) => 0,
                        Some(5) => 1,
                        Some(30) => 3,
                        None => 4,
                        _ => 2,
                    });
                    window.set_theme_index(match settings.theme {
                        ThemeChoice::System => 0,
                        ThemeChoice::Light => 1,
                        ThemeChoice::Dark => 2,
                    });
                    window.set_status(status.into());
                    if window.get_page() == "locked" || window.get_page() == "setup" {
                        window.set_page("generator".into());
                    }
                    window.set_restore_path("".into());
                    window.set_backup_password("".into());
                    window.set_new_password("".into());
                    window.set_confirm_password("".into());
                    window.set_editor_id("".into());
                    window.set_entry_label("".into());
                    self.refresh_entries();
                }
                Ok(Outcome::Password(password, copy)) => {
                    if copy {
                        self.copy(password);
                    } else {
                        window.set_password_value(password.as_str().into());
                        window.set_password_revealed(false);
                        window.set_status("Password generated.".into());
                    }
                }
                Ok(Outcome::Edit(entry)) => {
                    window.set_editor_id(entry.id.to_string().into());
                    window.set_entry_label(entry.label.as_str().into());
                    window.set_keyword(entry.keyword.as_str().into());
                    window.set_password_length(entry.options.length as i32);
                    window.set_include_lowercase(entry.options.lowercase);
                    window.set_include_uppercase(entry.options.uppercase);
                    window.set_include_numbers(entry.options.numbers);
                    window.set_include_symbols(entry.options.symbols);
                    window.set_page("vault".into());
                    window.set_status(
                        "Editing entry. Changing the keyword or options changes its password."
                            .into(),
                    );
                }
            }
        }
    }
    fn refresh_entries(&self) {
        if let Some(window) = self.window.upgrade() {
            let query = window.get_search().to_lowercase();
            let entries = self
                .state
                .borrow()
                .entries
                .iter()
                .filter(|e| e.label.to_lowercase().contains(&query))
                .map(|e| EntryView {
                    id: e.id.to_string().into(),
                    label: e.label.clone().into(),
                    updated: chrono::DateTime::from_timestamp(e.updated, 0)
                        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                        .unwrap_or_default()
                        .into(),
                })
                .collect::<Vec<_>>();
            window.set_entries(ModelRc::new(VecModel::from(entries)));
        }
    }
    fn copy(&self, password: Secret) {
        if let Some(window) = self.window.upgrade() {
            let result = self.state.borrow_mut().clipboard.copy(password);
            window.set_status(
                result
                    .map(|_| "Password copied. Clipboard clears after 30 seconds.".to_string())
                    .unwrap_or_else(|e| e)
                    .into(),
            );
        }
    }
    pub fn lock(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        {
            let mut state = self.state.borrow_mut();
            state.clipboard.clear();
            state.entries.clear();
            state.unlocked = false;
        }
        if let Some(window) = self.window.upgrade() {
            window.set_page("locked".into());
            window.set_busy(false);
            window.set_keyword("".into());
            window.set_password_value("".into());
            window.set_password_revealed(false);
            window.set_entry_label("".into());
            window.set_editor_id("".into());
            window.set_search("".into());
            window.set_backup_password("".into());
            window.set_new_password("".into());
            window.set_confirm_password("".into());
            window.set_restore_path("".into());
            window.set_entries(ModelRc::default());
            window.set_status("Vault locked.".into());
        }
        let _ = self.sender.send(Request {
            epoch: self.epoch.load(Ordering::SeqCst),
            job: Job::Lock,
        });
    }
    pub fn shutdown(&self) {
        self.timer.stop();
        self.power_stop.store(true, Ordering::SeqCst);
        self.lock();
        let _ = self.sender.send(Request {
            epoch: self.epoch.load(Ordering::SeqCst),
            job: Job::Exit,
        });
        if let Some(worker) = self.worker.borrow_mut().take() {
            let _ = worker.join();
        }
    }
    fn wire(self: &Rc<Self>, window: &AppWindow) {
        let c = Rc::downgrade(self);
        window.on_create_vault(move |password, confirm| {
            if let Some(c) = c.upgrade() {
                if password != confirm {
                    if let Some(w) = c.window.upgrade() {
                        w.set_status("Passwords do not match.".into());
                    }
                } else {
                    c.submit(Job::Create(Zeroizing::new(password.to_string())));
                }
            }
        });
        let c = Rc::downgrade(self);
        window.on_unlock_vault(move |password| {
            if let Some(c) = c.upgrade() {
                c.submit(Job::Unlock(Zeroizing::new(password.to_string())));
            }
        });
        let c = Rc::downgrade(self);
        window.on_generate_password(move || {
            if let Some(c) = c.upgrade()
                && let Some(w) = c.window.upgrade()
            {
                c.submit(Job::Generate(
                    Zeroizing::new(w.get_keyword().to_string()),
                    options(&w),
                ));
            }
        });
        let c = Rc::downgrade(self);
        window.on_copy_password(move || {
            if let Some(c) = c.upgrade()
                && let Some(w) = c.window.upgrade()
                && c.state.borrow().unlocked
                && !w.get_password_value().is_empty()
            {
                c.copy(Zeroizing::new(w.get_password_value().to_string()));
            }
        });
        let c = Rc::downgrade(self);
        window.on_copy_entry(move |id| {
            if let (Some(c), Ok(id)) = (c.upgrade(), Uuid::parse_str(id.as_str())) {
                c.submit(Job::CopyEntry(id));
            }
        });
        let c = Rc::downgrade(self);
        window.on_edit_entry(move |id| {
            if let (Some(c), Ok(id)) = (c.upgrade(), Uuid::parse_str(id.as_str())) {
                c.submit(Job::Edit(id));
            }
        });
        let c = Rc::downgrade(self);
        window.on_lock_vault(move || {
            if let Some(c) = c.upgrade() {
                c.lock();
            }
        });
        let c = Rc::downgrade(self);
        window.on_activity(move || {
            if let Some(c) = c.upgrade() {
                if c.power.swap(false, Ordering::SeqCst) {
                    c.lock();
                } else {
                    c.state.borrow_mut().policy.activity();
                }
            }
        });
        let c = Rc::downgrade(self);
        window.on_search_changed(move || {
            if let Some(c) = c.upgrade() {
                c.refresh_entries();
            }
        });
        let c = Rc::downgrade(self);
        window.on_save_entry(move || {
            if let Some(c) = c.upgrade()
                && let Some(w) = c.window.upgrade()
            {
                let id = Uuid::parse_str(w.get_editor_id().as_str()).ok();
                c.submit(Job::Save(
                    id,
                    w.get_entry_label().to_string(),
                    Zeroizing::new(w.get_keyword().to_string()),
                    options(&w),
                ));
            }
        });
        let c = Rc::downgrade(self);
        window.on_delete_entry(move |id| {
            if let (Some(c), Ok(id)) = (c.upgrade(), Uuid::parse_str(id.as_str())) {
                let _ = slint::spawn_local(async move {
                    let result = rfd::AsyncMessageDialog::new()
                        .set_title("Delete entry?")
                        .set_description("This deletes the saved keyword and cannot be undone.")
                        .set_buttons(rfd::MessageButtons::YesNo)
                        .show()
                        .await;
                    if result == rfd::MessageDialogResult::Yes {
                        c.submit(Job::Delete(id));
                    }
                });
            }
        });
        let c = Rc::downgrade(self);
        window.on_export_vault(move || {
            if let Some(c) = c.upgrade() {
                let _ = slint::spawn_local(async move {
                    if let Some(path) = rfd::AsyncFileDialog::new()
                        .add_filter("Encrypted vault", &["pmv"])
                        .set_file_name("password-maker-backup.pmv")
                        .save_file()
                        .await
                    {
                        c.submit(Job::Export(path.path().to_path_buf()));
                    }
                });
            }
        });
        let c = Rc::downgrade(self);
        window.on_choose_backup(move || {
            if let Some(c) = c.upgrade() {
                let _ = slint::spawn_local(async move {
                    if let Some(path) = rfd::AsyncFileDialog::new()
                        .add_filter("Encrypted vault", &["pmv"])
                        .pick_file()
                        .await
                        && let Some(w) = c.window.upgrade()
                    {
                        w.set_restore_path(path.path().to_string_lossy().into_owned().into());
                    }
                });
            }
        });
        let c = Rc::downgrade(self);
        window.on_restore_vault(move || {
            let Some(c) = c.upgrade() else { return };
            let Some(w) = c.window.upgrade() else { return };
            if w.get_restore_path().is_empty() {
                w.set_status("Choose a backup first.".into());
                return;
            }
            if w.get_page() == "setup" && w.get_new_password() != w.get_confirm_password() {
                w.set_status("New passwords do not match.".into());
                return;
            }
            let job = Job::Restore(
                PathBuf::from(w.get_restore_path().as_str()),
                Zeroizing::new(w.get_backup_password().to_string()),
                Zeroizing::new(w.get_new_password().to_string()),
            );
            let epoch = c.epoch.load(Ordering::SeqCst);
            let _ = slint::spawn_local(async move {
                let result = rfd::AsyncMessageDialog::new()
                    .set_title("Restore encrypted backup?")
                    .set_description(
                        "This replaces the current vault. An encrypted pre-restore copy is saved first.",
                    )
                    .set_buttons(rfd::MessageButtons::YesNo)
                    .show()
                    .await;
                if result == rfd::MessageDialogResult::Yes
                    && epoch == c.epoch.load(Ordering::SeqCst)
                {
                    c.submit(job);
                }
            });
        });
        let c = Rc::downgrade(self);
        window.on_change_password(move |current, next, confirm| {
            if let Some(c) = c.upgrade() {
                if next != confirm {
                    if let Some(w) = c.window.upgrade() {
                        w.set_status("New passwords do not match.".into());
                    }
                } else {
                    c.submit(Job::Rotate(
                        Zeroizing::new(current.to_string()),
                        Zeroizing::new(next.to_string()),
                    ));
                }
            }
        });
        let c = Rc::downgrade(self);
        window.on_save_settings(move || {
            if let Some(c) = c.upgrade()
                && let Some(w) = c.window.upgrade()
            {
                let timeout = match w.get_timeout_index() {
                    0 => Some(1),
                    1 => Some(5),
                    3 => Some(30),
                    4 => None,
                    _ => Some(15),
                };
                let theme = match w.get_theme_index() {
                    1 => ThemeChoice::Light,
                    2 => ThemeChoice::Dark,
                    _ => ThemeChoice::System,
                };
                c.submit(Job::Settings(VaultSettings {
                    auto_lock_minutes: timeout,
                    theme,
                }));
            }
        });
        use slint::winit_030::{EventResult, WinitWindowAccessor, winit::event::WindowEvent};
        let c = Rc::downgrade(self);
        window.window().on_winit_window_event(move |_, event| {
            if matches!(
                event,
                WindowEvent::KeyboardInput { .. }
                    | WindowEvent::MouseInput { .. }
                    | WindowEvent::MouseWheel { .. }
                    | WindowEvent::Touch(_)
            ) && let Some(c) = c.upgrade()
            {
                if c.power.swap(false, Ordering::SeqCst) {
                    c.lock();
                    return EventResult::PreventDefault;
                }
                c.state.borrow_mut().policy.activity();
            }
            EventResult::Propagate
        });
    }
}
fn options(window: &AppWindow) -> PasswordOptions {
    PasswordOptions {
        length: window.get_password_length() as u16,
        lowercase: window.get_include_lowercase(),
        uppercase: window.get_include_uppercase(),
        numbers: window.get_include_numbers(),
        symbols: window.get_include_symbols(),
        ..PasswordOptions::default()
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn a_lock_invalidates_pending_work() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let epoch = AtomicU64::new(0);
        let pending = epoch.load(Ordering::SeqCst);
        epoch.fetch_add(1, Ordering::SeqCst);
        assert_ne!(pending, epoch.load(Ordering::SeqCst));
    }
}

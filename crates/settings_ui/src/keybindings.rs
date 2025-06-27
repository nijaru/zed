use std::{fmt::Write as _, ops::Range, sync::Arc};

use collections::HashSet;
use db::anyhow::anyhow;
use editor::{Editor, EditorEvent};
use fuzzy::{StringMatch, StringMatchCandidate};
use gpui::{
    AppContext as _, Context, DismissEvent, Entity, EventEmitter, FocusHandle, Focusable,
    FontWeight, Global, KeyContext, ScrollStrategy, Subscription, WeakEntity, actions, div,
};
use util::ResultExt;

use ui::{
    ActiveTheme as _, App, BorrowAppContext, ParentElement as _, Render, SharedString, Styled as _,
    Window, prelude::*,
};
use workspace::{Item, ModalView, SerializableItem, Workspace, register_serializable_item};

use crate::{
    keybindings::persistence::KEYBINDING_EDITORS,
    ui_components::table::{Table, TableInteractionState},
};

actions!(zed, [OpenKeymapEditor]);

pub fn init(cx: &mut App) {
    let keymap_event_channel = KeymapEventChannel::new();
    cx.set_global(keymap_event_channel);

    cx.observe_new(|workspace: &mut Workspace, _window, _cx| {
        workspace.register_action(|workspace, _: &OpenKeymapEditor, window, cx| {
            let open_keymap_editor =
                cx.new(|cx| KeymapEditor::new(workspace.weak_handle(), window, cx));
            workspace.add_item_to_center(Box::new(open_keymap_editor), window, cx);
        });
    })
    .detach();

    register_serializable_item::<KeymapEditor>(cx);
}

pub struct KeymapEventChannel {}

impl Global for KeymapEventChannel {}

impl KeymapEventChannel {
    fn new() -> Self {
        Self {}
    }

    pub fn trigger_keymap_changed(cx: &mut App) {
        cx.update_global(|_event_channel: &mut Self, _| {
            /* triggers observers in KeymapEditors */
        });
    }
}

struct KeymapEditor {
    workspace: WeakEntity<Workspace>,
    focus_handle: FocusHandle,
    _keymap_subscription: Subscription,
    keybindings: Vec<ProcessedKeybinding>,
    // corresponds 1 to 1 with keybindings
    string_match_candidates: Arc<Vec<StringMatchCandidate>>,
    matches: Vec<StringMatch>,
    table_interaction_state: Entity<TableInteractionState>,
    filter_editor: Entity<Editor>,
    selected_index: Option<usize>,
}

impl EventEmitter<()> for KeymapEditor {}

impl Focusable for KeymapEditor {
    fn focus_handle(&self, cx: &App) -> gpui::FocusHandle {
        return self.filter_editor.focus_handle(cx);
    }
}

impl KeymapEditor {
    fn new(workspace: WeakEntity<Workspace>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus_handle = cx.focus_handle();

        let _keymap_subscription =
            cx.observe_global::<KeymapEventChannel>(Self::update_keybindings);
        let table_interaction_state = TableInteractionState::new(window, cx);

        let filter_editor = cx.new(|cx| {
            let mut editor = Editor::single_line(window, cx);
            editor.set_placeholder_text("Filter action names...", cx);
            editor
        });

        cx.subscribe(&filter_editor, |this, _, e: &EditorEvent, cx| {
            if !matches!(e, EditorEvent::BufferEdited) {
                return;
            }

            this.update_matches(cx);
        })
        .detach();

        let mut this = Self {
            workspace,
            keybindings: vec![],
            string_match_candidates: Arc::new(vec![]),
            matches: vec![],
            focus_handle: focus_handle.clone(),
            _keymap_subscription,
            table_interaction_state,
            filter_editor,
            selected_index: None,
        };

        this.update_keybindings(cx);

        this
    }

    fn update_matches(&mut self, cx: &mut Context<Self>) {
        let query = self.filter_editor.read(cx).text(cx);
        let string_match_candidates = self.string_match_candidates.clone();
        let executor = cx.background_executor().clone();
        let keybind_count = self.keybindings.len();
        let query = command_palette::normalize_action_query(&query);
        let fuzzy_match = cx.background_spawn(async move {
            fuzzy::match_strings(
                &string_match_candidates,
                &query,
                true,
                true,
                keybind_count,
                &Default::default(),
                executor,
            )
            .await
        });

        cx.spawn(async move |this, cx| {
            let matches = fuzzy_match.await;
            this.update(cx, |this, cx| {
                this.selected_index.take();
                this.scroll_to_item(0, ScrollStrategy::Top, cx);
                this.matches = matches;
                cx.notify();
            })
        })
        .detach();
    }

    fn process_bindings(
        cx: &mut Context<Self>,
    ) -> (Vec<ProcessedKeybinding>, Vec<StringMatchCandidate>) {
        let key_bindings_ptr = cx.key_bindings();
        let lock = key_bindings_ptr.borrow();
        let key_bindings = lock.bindings();
        let mut unmapped_action_names = HashSet::from_iter(cx.all_action_names());

        let mut processed_bindings = Vec::new();
        let mut string_match_candidates = Vec::new();

        for key_binding in key_bindings {
            let source = key_binding
                .meta()
                .map(|meta| settings::KeybindSource::from_meta(meta));

            let keystroke_text = ui::text_for_keystrokes(key_binding.keystrokes(), cx);
            let ui_key_binding = Some(
                ui::KeyBinding::new(key_binding.clone(), cx)
                    .vim_mode(source == Some(settings::KeybindSource::Vim)),
            );

            let context = key_binding
                .predicate()
                .map(|predicate| predicate.to_string())
                .unwrap_or_else(|| "<global>".to_string());

            let source = source.map(|source| source.name().into());

            let action_name = key_binding.action().name();
            unmapped_action_names.remove(&action_name);

            let index = processed_bindings.len();
            let string_match_candidate = StringMatchCandidate::new(index, &action_name);
            processed_bindings.push(ProcessedKeybinding {
                keystroke_text: keystroke_text.into(),
                ui_key_binding,
                action: action_name.into(),
                action_input: key_binding.action_input(),
                context: context.into(),
                source,
            });
            string_match_candidates.push(string_match_candidate);
        }

        let empty = SharedString::new_static("");
        for action_name in unmapped_action_names.into_iter() {
            let index = processed_bindings.len();
            let string_match_candidate = StringMatchCandidate::new(index, &action_name);
            processed_bindings.push(ProcessedKeybinding {
                keystroke_text: empty.clone(),
                ui_key_binding: None,
                action: (*action_name).into(),
                action_input: None,
                context: empty.clone(),
                source: None,
            });
            string_match_candidates.push(string_match_candidate);
        }

        (processed_bindings, string_match_candidates)
    }

    fn update_keybindings(self: &mut KeymapEditor, cx: &mut Context<KeymapEditor>) {
        let (key_bindings, string_match_candidates) = Self::process_bindings(cx);
        self.keybindings = key_bindings;
        self.string_match_candidates = Arc::new(string_match_candidates);
        self.matches = self
            .string_match_candidates
            .iter()
            .enumerate()
            .map(|(ix, candidate)| StringMatch {
                candidate_id: ix,
                score: 0.0,
                positions: vec![],
                string: candidate.string.clone(),
            })
            .collect();

        self.update_matches(cx);
        cx.notify();
    }

    fn dispatch_context(&self, _window: &Window, _cx: &Context<Self>) -> KeyContext {
        let mut dispatch_context = KeyContext::new_with_defaults();
        dispatch_context.add("KeymapEditor");
        dispatch_context.add("menu");

        // todo! track key context in keybind edit modal
        // let identifier = if self.keymap_editor.focus_handle(cx).is_focused(window) {
        //     "editing"
        // } else {
        //     "not_editing"
        // };
        // dispatch_context.add(identifier);

        dispatch_context
    }

    fn scroll_to_item(&self, index: usize, strategy: ScrollStrategy, cx: &mut App) {
        let index = usize::min(index, self.matches.len().saturating_sub(1));
        self.table_interaction_state.update(cx, |this, _cx| {
            this.scroll_handle.scroll_to_item(index, strategy);
        });
    }

    fn select_next(&mut self, _: &menu::SelectNext, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(selected) = self.selected_index {
            let selected = selected + 1;
            if selected >= self.matches.len() {
                self.select_last(&Default::default(), window, cx);
            } else {
                self.selected_index = Some(selected);
                self.scroll_to_item(selected, ScrollStrategy::Center, cx);
                cx.notify();
            }
        } else {
            self.select_first(&Default::default(), window, cx);
        }
    }

    fn select_previous(
        &mut self,
        _: &menu::SelectPrevious,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(selected) = self.selected_index {
            if selected == 0 {
                return;
            }

            let selected = selected - 1;

            if selected >= self.matches.len() {
                self.select_last(&Default::default(), window, cx);
            } else {
                self.selected_index = Some(selected);
                self.scroll_to_item(selected, ScrollStrategy::Center, cx);
                cx.notify();
            }
        } else {
            self.select_last(&Default::default(), window, cx);
        }
    }

    fn select_first(
        &mut self,
        _: &menu::SelectFirst,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.matches.get(0).is_some() {
            self.selected_index = Some(0);
            self.scroll_to_item(0, ScrollStrategy::Center, cx);
            cx.notify();
        }
    }

    fn select_last(&mut self, _: &menu::SelectLast, _window: &mut Window, cx: &mut Context<Self>) {
        if self.matches.last().is_some() {
            let index = self.matches.len() - 1;
            self.selected_index = Some(index);
            self.scroll_to_item(index, ScrollStrategy::Center, cx);
            cx.notify();
        }
    }

    fn confirm(&mut self, _: &menu::Confirm, window: &mut Window, cx: &mut Context<Self>) {
        let Some(index) = self.selected_index else {
            return;
        };
        let keybind = self.keybindings[self.matches[index].candidate_id].clone();

        self.edit_keybinding(keybind, window, cx);
    }

    fn edit_keybinding(
        &mut self,
        keybind: ProcessedKeybinding,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        // todo! how to map keybinds to how to update/edit them
        _ = keybind;
        self.workspace
            .update(cx, |workspace, cx| {
                workspace.toggle_modal(window, cx, |window, cx| {
                    let modal = KeybindingEditorModal::new(window, cx);
                    window.focus(&modal.focus_handle(cx));
                    modal
                });
            })
            .log_err();
    }

    fn focus_search(
        &mut self,
        _: &search::FocusSearch,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self
            .filter_editor
            .focus_handle(cx)
            .contains_focused(window, cx)
        {
            window.focus(&self.filter_editor.focus_handle(cx));
        } else {
            self.filter_editor.update(cx, |editor, cx| {
                editor.select_all(&Default::default(), window, cx);
            });
        }
        self.selected_index.take();
    }
}

#[derive(Clone)]
struct ProcessedKeybinding {
    keystroke_text: SharedString,
    ui_key_binding: Option<ui::KeyBinding>,
    action: SharedString,
    action_input: Option<SharedString>,
    context: SharedString,
    source: Option<SharedString>,
}

impl Item for KeymapEditor {
    type Event = ();

    fn tab_content_text(&self, _detail: usize, _cx: &App) -> ui::SharedString {
        "Keymap Editor".into()
    }
}

impl Render for KeymapEditor {
    fn render(&mut self, window: &mut Window, cx: &mut ui::Context<Self>) -> impl ui::IntoElement {
        let row_count = self.matches.len();
        let theme = cx.theme();

        div()
            .key_context(self.dispatch_context(window, cx))
            .on_action(cx.listener(Self::select_next))
            .on_action(cx.listener(Self::select_previous))
            .on_action(cx.listener(Self::select_first))
            .on_action(cx.listener(Self::select_last))
            .on_action(cx.listener(Self::focus_search))
            .on_action(cx.listener(Self::confirm))
            .size_full()
            .bg(theme.colors().editor_background)
            .id("keymap-editor")
            .track_focus(&self.focus_handle)
            .px_4()
            .v_flex()
            .pb_4()
            .child(
                h_flex()
                    .key_context({
                        let mut context = KeyContext::new_with_defaults();
                        context.add("BufferSearchBar");
                        context
                    })
                    .w_full()
                    .h_12()
                    .px_4()
                    .my_4()
                    .border_2()
                    .border_color(theme.colors().border)
                    .child(self.filter_editor.clone()),
            )
            .child(
                Table::new()
                    .interactable(&self.table_interaction_state)
                    .striped()
                    .column_widths([rems(24.), rems(16.), rems(32.), rems(8.)])
                    .header(["Command", "Keystrokes", "Context", "Source"])
                    .selected_item_index(self.selected_index.clone())
                    .on_click_row(cx.processor(|this, row_index, _window, _cx| {
                        this.selected_index = Some(row_index);
                    }))
                    .uniform_list(
                        "keymap-editor-table",
                        row_count,
                        cx.processor(move |this, range: Range<usize>, _window, _cx| {
                            range
                                .filter_map(|index| {
                                    let candidate_id = this.matches.get(index)?.candidate_id;
                                    let binding = &this.keybindings[candidate_id];
                                    let action = h_flex()
                                        .items_start()
                                        .gap_1()
                                        .child(binding.action.clone())
                                        .when_some(
                                            binding.action_input.clone(),
                                            |this, binding_input| this.child(binding_input),
                                        );
                                    let keystrokes = binding.ui_key_binding.clone().map_or(
                                        binding.keystroke_text.clone().into_any_element(),
                                        IntoElement::into_any_element,
                                    );
                                    let context = binding.context.clone();
                                    let source = binding.source.clone().unwrap_or_default();
                                    Some([
                                        action.into_any_element(),
                                        keystrokes,
                                        context.into_any_element(),
                                        source.into_any_element(),
                                    ])
                                })
                                .collect()
                        }),
                    ),
            )
    }
}

struct KeybindingEditorModal {
    keybind_editor: Entity<Editor>,
}

impl ModalView for KeybindingEditorModal {}

impl EventEmitter<DismissEvent> for KeybindingEditorModal {}

impl Focusable for KeybindingEditorModal {
    fn focus_handle(&self, cx: &App) -> FocusHandle {
        self.keybind_editor.focus_handle(cx)
    }
}

impl KeybindingEditorModal {
    pub fn new(window: &mut Window, cx: &mut App) -> Self {
        let keybind_editor = cx.new(|cx| {
            let editor = Editor::single_line(window, cx);
            editor
        });
        Self { keybind_editor }
    }
}

impl Render for KeybindingEditorModal {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().colors();
        return v_flex()
            .items_center()
            .text_center()
            .bg(theme.background)
            .border_color(theme.border)
            .border_2()
            .px_4()
            .py_2()
            .w(rems(36.))
            .child(div().text_lg().font_weight(FontWeight::BOLD).child(
                // todo! better text
                "Input desired keybinding, then hit Enter to save",
            ))
            .child(
                h_flex()
                    .w_full()
                    .h_12()
                    .px_4()
                    .my_4()
                    .border_2()
                    .border_color(theme.border)
                    .child(self.keybind_editor.clone()),
            );
    }
}

impl SerializableItem for KeymapEditor {
    fn serialized_item_kind() -> &'static str {
        "KeymapEditor"
    }

    fn cleanup(
        workspace_id: workspace::WorkspaceId,
        alive_items: Vec<workspace::ItemId>,
        _window: &mut Window,
        cx: &mut App,
    ) -> gpui::Task<gpui::Result<()>> {
        workspace::delete_unloaded_items(
            alive_items,
            workspace_id,
            "keybinding_editors",
            &KEYBINDING_EDITORS,
            cx,
        )
    }

    fn deserialize(
        _project: Entity<project::Project>,
        workspace: WeakEntity<Workspace>,
        workspace_id: workspace::WorkspaceId,
        item_id: workspace::ItemId,
        window: &mut Window,
        cx: &mut App,
    ) -> gpui::Task<gpui::Result<Entity<Self>>> {
        window.spawn(cx, async move |cx| {
            if KEYBINDING_EDITORS
                .get_keybinding_editor(item_id, workspace_id)?
                .is_some()
            {
                cx.update(|window, cx| cx.new(|cx| KeymapEditor::new(workspace, window, cx)))
            } else {
                Err(anyhow!("No keybinding editor to deserialize"))
            }
        })
    }

    fn serialize(
        &mut self,
        workspace: &mut Workspace,
        item_id: workspace::ItemId,
        _closing: bool,
        _window: &mut Window,
        cx: &mut ui::Context<Self>,
    ) -> Option<gpui::Task<gpui::Result<()>>> {
        let workspace_id = workspace.database_id()?;
        Some(cx.background_spawn(async move {
            KEYBINDING_EDITORS
                .save_keybinding_editor(item_id, workspace_id)
                .await
        }))
    }

    fn should_serialize(&self, _event: &Self::Event) -> bool {
        false
    }
}

mod persistence {
    use db::{define_connection, query, sqlez_macros::sql};
    use workspace::WorkspaceDb;

    define_connection! {
        pub static ref KEYBINDING_EDITORS: KeybindingEditorDb<WorkspaceDb> =
            &[sql!(
                CREATE TABLE keybinding_editors (
                    workspace_id INTEGER,
                    item_id INTEGER UNIQUE,

                    PRIMARY KEY(workspace_id, item_id),
                    FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id)
                    ON DELETE CASCADE
                ) STRICT;
            )];
    }

    impl KeybindingEditorDb {
        query! {
            pub async fn save_keybinding_editor(
                item_id: workspace::ItemId,
                workspace_id: workspace::WorkspaceId
            ) -> Result<()> {
                INSERT OR REPLACE INTO keybinding_editors(item_id, workspace_id)
                VALUES (?, ?)
            }
        }

        query! {
            pub fn get_keybinding_editor(
                item_id: workspace::ItemId,
                workspace_id: workspace::WorkspaceId
            ) -> Result<Option<workspace::ItemId>> {
                SELECT item_id
                FROM keybinding_editors
                WHERE item_id = ? AND workspace_id = ?
            }
        }
    }
}

#include <windows.h>
#include <commctrl.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "credential_vault.hpp"
#include "crypto_utils.hpp"
#include "integrity.hpp"

#ifndef LR1_CHECK_IS_DEBUGGER_PRESENT
#define LR1_CHECK_IS_DEBUGGER_PRESENT 0
#endif

namespace {

using lr1::CredentialVault;
using lr1::Field;

constexpr wchar_t kWindowClassName[] = L"LR1PassManagerWindow";
constexpr wchar_t kWindowTitle[] = L"Менеджер паролей (ЛР1)";
constexpr wchar_t kVaultFileName[] = L"credentials.bin";
constexpr wchar_t kMaskedValue[] = L"••••••••";
constexpr std::size_t kMinPinLength = 4;

enum ControlId : int {
    IdUnlockLabel = 101,
    IdPinEdit,
    IdUnlockButton,
    IdWarningLabel,
    IdSearchEdit = 201,
    IdEntryList,
    IdMenuCopyLogin = 301,
    IdMenuCopyPassword,
};

enum class Screen { Unlock, List };

enum class PendingAction { OpenVault, RevealLogin, RevealPassword };

struct AppState {
    HWND window = nullptr;
    CredentialVault vault;
    std::filesystem::path vaultPath;
    Screen screen = Screen::Unlock;
    PendingAction pending = PendingAction::OpenVault;
    std::size_t pendingIndex = 0;
    bool locked = false;

    HFONT font = nullptr;
    HWND unlockLabel = nullptr;
    HWND pinEdit = nullptr;
    HWND unlockButton = nullptr;
    HWND warningLabel = nullptr;
    HWND searchEdit = nullptr;
    HWND entryList = nullptr;
    WNDPROC originalPinEditProc = nullptr;
};

LRESULT CALLBACK PinEditProc(HWND edit, UINT message, WPARAM wParam, LPARAM lParam);

HMENU controlId(int id) {
    return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

std::string toUtf8(const std::wstring& text) {
    if (text.empty()) {
        return std::string();
    }
    const int length = WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                           static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &result[0],
                        length, nullptr, nullptr);
    return result;
}

std::wstring fromUtf8(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    const int length = MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                           static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &result[0], length);
    return result;
}

std::wstring windowText(HWND window) {
    const int length = GetWindowTextLengthW(window);
    std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 1, L'\0');
    GetWindowTextW(window, buffer.data(), length + 1);
    return std::wstring(buffer.data());
}

std::string toLowerAscii(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char symbol) { return static_cast<char>(std::tolower(symbol)); });
    return text;
}

std::filesystem::path executableDirectory() {
    std::vector<wchar_t> buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    return std::filesystem::path(std::wstring(buffer.data(), length)).parent_path();
}

void showScreen(AppState& state, Screen screen) {
    state.screen = screen;
    const bool unlock = (screen == Screen::Unlock);
    for (HWND control : {state.unlockLabel, state.pinEdit, state.unlockButton, state.warningLabel}) {
        ShowWindow(control, unlock ? SW_SHOW : SW_HIDE);
    }
    for (HWND control : {state.searchEdit, state.entryList}) {
        ShowWindow(control, unlock ? SW_HIDE : SW_SHOW);
    }
}

void setWarning(AppState& state, const std::wstring& text) {
    SetWindowTextW(state.warningLabel, text.c_str());
}

void layoutControls(HWND window, const AppState& state) {
    RECT client{};
    GetClientRect(window, &client);
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;

    const int editWidth = std::min(320, std::max(160, width - 80));
    const int editLeft = (width - editWidth) / 2;
    const int top = std::max(40, height / 2 - 80);
    MoveWindow(state.unlockLabel, 20, top, width - 40, 24, TRUE);
    MoveWindow(state.pinEdit, editLeft, top + 34, editWidth, 26, TRUE);
    MoveWindow(state.unlockButton, (width - 140) / 2, top + 74, 140, 30, TRUE);
    MoveWindow(state.warningLabel, 20, top + 120, width - 40, 40, TRUE);

    MoveWindow(state.searchEdit, 8, 8, width - 16, 26, TRUE);
    MoveWindow(state.entryList, 8, 42, width - 16, std::max(0, height - 50), TRUE);
}

void addColumn(HWND list, int index, int width, const wchar_t* title) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.cx = width;
    column.pszText = const_cast<wchar_t*>(title);
    column.iSubItem = index;
    ListView_InsertColumn(list, index, &column);
}

void createControls(HWND window, AppState& state) {
    HINSTANCE instance = GetModuleHandleW(nullptr);
    state.font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

    state.unlockLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_CENTER,
                                        0, 0, 0, 0, window, controlId(IdUnlockLabel), instance, nullptr);
    state.pinEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_CENTER | ES_AUTOHSCROLL,
                                    0, 0, 0, 0, window, controlId(IdPinEdit), instance, nullptr);
    state.unlockButton = CreateWindowExW(0, L"BUTTON", L"Войти",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                         0, 0, 0, 0, window, controlId(IdUnlockButton), instance, nullptr);
    state.warningLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_CENTER,
                                         0, 0, 0, 0, window, controlId(IdWarningLabel), instance, nullptr);

    state.searchEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                       WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
                                       0, 0, 0, 0, window, controlId(IdSearchEdit), instance, nullptr);
    state.entryList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                      WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                      0, 0, 0, 0, window, controlId(IdEntryList), instance, nullptr);
    ListView_SetExtendedListViewStyle(state.entryList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    addColumn(state.entryList, 0, 330, L"Сайт (URL)");
    addColumn(state.entryList, 1, 170, L"Логин");
    addColumn(state.entryList, 2, 170, L"Пароль");

    for (HWND control : {state.unlockLabel, state.pinEdit, state.unlockButton, state.warningLabel,
                         state.searchEdit, state.entryList}) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(state.font), TRUE);
    }
    SetWindowTextW(state.unlockLabel, L"Введите пин-код для разблокировки хранилища");
    state.originalPinEditProc = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(state.pinEdit, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(PinEditProc)));
    showScreen(state, Screen::Unlock);
}

void populateList(AppState& state) {
    const std::string filter = toLowerAscii(toUtf8(windowText(state.searchEdit)));
    ListView_DeleteAllItems(state.entryList);
    const auto& entries = state.vault.entries();
    int row = 0;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        if (!filter.empty() && toLowerAscii(entries[index].url).find(filter) == std::string::npos) {
            continue;
        }
        std::wstring url = fromUtf8(entries[index].url);
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = row;
        item.lParam = static_cast<LPARAM>(index);
        item.pszText = &url[0];
        ListView_InsertItem(state.entryList, &item);
        ListView_SetItemText(state.entryList, row, 1, const_cast<wchar_t*>(kMaskedValue));
        ListView_SetItemText(state.entryList, row, 2, const_cast<wchar_t*>(kMaskedValue));
        ++row;
    }
}

bool selectedEntryIndex(const AppState& state, std::size_t& index) {
    const int row = ListView_GetNextItem(state.entryList, -1, LVNI_SELECTED);
    if (row < 0) {
        return false;
    }
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = row;
    ListView_GetItem(state.entryList, &item);
    index = static_cast<std::size_t>(item.lParam);
    return true;
}

bool copyToClipboard(HWND owner, const std::string& utf8Text) {
    std::wstring text = fromUtf8(utf8Text);
    const std::size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory == nullptr) {
        SecureZeroMemory(&text[0], text.size() * sizeof(wchar_t));
        return false;
    }
    std::memcpy(GlobalLock(memory), text.c_str(), bytes);
    GlobalUnlock(memory);
    SecureZeroMemory(&text[0], text.size() * sizeof(wchar_t));

    if (!OpenClipboard(owner)) {
        GlobalFree(memory);
        return false;
    }
    EmptyClipboard();
    const bool stored = SetClipboardData(CF_UNICODETEXT, memory) != nullptr;
    CloseClipboard();
    if (!stored) {
        GlobalFree(memory);
    }
    return stored;
}

void lockForAttack(HWND window, AppState& state, const std::wstring& reason) {
    state.locked = true;
    EnableWindow(state.pinEdit, FALSE);
    EnableWindow(state.unlockButton, FALSE);
    showScreen(state, Screen::Unlock);
    SetWindowTextW(state.unlockLabel, L"Работа приложения заблокирована");
    setWarning(state, L"Обнаружена атака: " + reason + L". Ввод пин-кода заблокирован.");
    MessageBoxW(window, (L"Обнаружена атака: " + reason + L".").c_str(),
                L"Предупреждение безопасности", MB_OK | MB_ICONWARNING);
}

void runStartupChecks(HWND window, AppState& state) {
#if LR1_CHECK_IS_DEBUGGER_PRESENT
    if (lr1::isDebuggerAttached()) {
        MessageBoxW(window, L"Обнаружен отладчик. Работа приложения прекращена.",
                    L"Предупреждение безопасности", MB_OK | MB_ICONWARNING);
        PostMessageW(window, WM_CLOSE, 0, 0);
        return;
    }
#endif
    std::string error;
    if (!lr1::isTextSegmentIntact(error)) {
        lockForAttack(window, state, L"нарушена целостность кода (самопроверка сегмента .text)");
    }
}

void beginReveal(AppState& state, std::size_t entryIndex, Field field) {
    if (state.locked) {
        return;
    }
    state.pending = (field == Field::Login) ? PendingAction::RevealLogin : PendingAction::RevealPassword;
    state.pendingIndex = entryIndex;
    SetWindowTextW(state.unlockLabel, L"Введите пин-код для расшифровки учётной записи");
    SetWindowTextW(state.window, L"Подтверждение пин-кода");
    SetWindowTextW(state.pinEdit, L"");
    setWarning(state, L"");
    showScreen(state, Screen::Unlock);
    SetFocus(state.pinEdit);
}

void cancelReveal(AppState& state) {
    SetWindowTextW(state.pinEdit, L"");
    SetWindowTextW(state.window, L"Учётные данные");
    setWarning(state, L"");
    showScreen(state, Screen::List);
    SetFocus(state.entryList);
}

void submitPin(HWND window, AppState& state) {
    if (state.locked) {
        return;
    }
    std::wstring pinText = windowText(state.pinEdit);
    std::string pin = toUtf8(pinText);
    SecureZeroMemory(&pinText[0], pinText.size() * sizeof(wchar_t));

    if (pin.size() < kMinPinLength) {
        setWarning(state, L"Пин-код должен содержать не менее 4 символов");
        lr1::wipe(pin);
        return;
    }

    if (state.pending == PendingAction::OpenVault) {
        std::string error;
        const bool opened = state.vault.load(state.vaultPath, pin, error);
        lr1::wipe(pin);
        if (!opened) {
            setWarning(state, L"Ошибка: " + fromUtf8(error));
            return;
        }
        SetWindowTextW(state.pinEdit, L"");
        showScreen(state, Screen::List);
        populateList(state);
        SetWindowTextW(window, L"Учётные данные");
        return;
    }

    const Field field = (state.pending == PendingAction::RevealLogin) ? Field::Login : Field::Password;
    std::string value;
    const bool revealed = state.vault.reveal(state.pendingIndex, field, pin, value);
    lr1::wipe(pin);
    if (!revealed) {
        setWarning(state, L"Неверный пин-код: расшифровка не выполнена");
        lr1::wipe(value);
        return;
    }
    const bool copied = copyToClipboard(window, value);
    lr1::wipe(value);
    state.pending = PendingAction::OpenVault;
    cancelReveal(state);
    if (copied) {
        SetWindowTextW(window, (field == Field::Login) ? L"Логин скопирован в буфер обмена"
                                                       : L"Пароль скопирован в буфер обмена");
    } else {
        SetWindowTextW(window, L"Не удалось скопировать значение в буфер обмена");
    }
}

void showEntryMenu(HWND window, const AppState& state) {
    std::size_t index = 0;
    if (!selectedEntryIndex(state, index)) {
        return;
    }
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, IdMenuCopyLogin, L"Скопировать логин");
    AppendMenuW(menu, MF_STRING, IdMenuCopyPassword, L"Скопировать пароль");
    POINT cursor{};
    GetCursorPos(&cursor);
    SetForegroundWindow(window);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, cursor.x, cursor.y, 0, window, nullptr);
    DestroyMenu(menu);
}

void handleCommand(HWND window, AppState& state, int id, int notification) {
    switch (id) {
    case IdUnlockButton:
        if (notification == BN_CLICKED) {
            submitPin(window, state);
        }
        break;
    case IdSearchEdit:
        if (notification == EN_CHANGE && state.screen == Screen::List) {
            populateList(state);
        }
        break;
    case IdMenuCopyLogin:
    case IdMenuCopyPassword: {
        std::size_t index = 0;
        if (selectedEntryIndex(state, index)) {
            beginReveal(state, index, id == IdMenuCopyLogin ? Field::Login : Field::Password);
        }
        break;
    }
    default:
        break;
    }
}

void handleListNotify(HWND window, AppState& state, const NMHDR* header) {
    switch (header->code) {
    case NM_DBLCLK:
    case NM_RETURN: {
        std::size_t index = 0;
        if (selectedEntryIndex(state, index)) {
            const bool loginRequested = header->code == NM_RETURN &&
                                        (GetKeyState(VK_CONTROL) & 0x8000) != 0;
            beginReveal(state, index, loginRequested ? Field::Login : Field::Password);
        }
        break;
    }
    case NM_RCLICK:
        showEntryMenu(window, state);
        break;
    default:
        break;
    }
}

LRESULT CALLBACK PinEditProc(HWND edit, UINT message, WPARAM wParam, LPARAM lParam) {
    HWND window = GetParent(edit);
    auto* state = reinterpret_cast<AppState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (state == nullptr) {
        return DefWindowProcW(edit, message, wParam, lParam);
    }
    if (message == WM_CHAR && wParam == VK_RETURN) {
        return 0;
    }
    if (message == WM_KEYDOWN && wParam == VK_RETURN) {
        SendMessageW(window, WM_COMMAND, MAKEWPARAM(IdUnlockButton, BN_CLICKED),
                     reinterpret_cast<LPARAM>(state->unlockButton));
        return 0;
    }
    if (message == WM_KEYDOWN && wParam == VK_ESCAPE && state->screen == Screen::Unlock &&
        state->pending != PendingAction::OpenVault) {
        cancelReveal(*state);
        return 0;
    }
    return CallWindowProcW(state->originalPinEditProc, edit, message, wParam, lParam);
}

LRESULT CALLBACK MainWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<AppState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    switch (message) {
    case WM_CREATE: {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        state = static_cast<AppState*>(create->lpCreateParams);
        state->window = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        createControls(window, *state);
        return 0;
    }
    case WM_SIZE:
        if (state != nullptr) {
            layoutControls(window, *state);
        }
        return 0;
    case WM_COMMAND:
        if (state != nullptr) {
            handleCommand(window, *state, LOWORD(wParam), HIWORD(wParam));
        }
        return 0;
    case WM_NOTIFY: {
        const auto* header = reinterpret_cast<const NMHDR*>(lParam);
        if (state != nullptr && header->idFrom == IdEntryList) {
            handleListNotify(window, *state, header);
        }
        return 0;
    }
    case WM_DESTROY:
        if (state != nullptr) {
            state->vault.clear();
        }
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE , PWSTR ,
                    int showCommand) {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&controls);

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = MainWindowProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = kWindowClassName;
    if (RegisterClassExW(&windowClass) == 0) {
        return 1;
    }

    AppState state;
    state.vaultPath = executableDirectory() / kVaultFileName;
    HWND window = CreateWindowExW(0, kWindowClassName, kWindowTitle, WS_OVERLAPPEDWINDOW,
                                  CW_USEDEFAULT, CW_USEDEFAULT, 760, 480, nullptr, nullptr,
                                  instance, &state);
    if (window == nullptr) {
        return 1;
    }
    ShowWindow(window, showCommand);
    UpdateWindow(window);
    runStartupChecks(window, state);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}

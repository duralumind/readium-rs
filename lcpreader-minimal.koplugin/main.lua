local DocumentRegistry = require("document/documentregistry")
local InfoMessage = require("ui/widget/infomessage")
local InputDialog = require("ui/widget/inputdialog")
local UIManager = require("ui/uimanager")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local ffi = require("ffi")
local logger = require("logger")
local util = require("util")
local _ = require("gettext")
local T = require("ffi/util").template

local PASSPHRASE_CACHE_KEY = "lcp_minimal_passphrase_cache"

ffi.cdef[[
    int lcp_init(void);
    int lcp_is_encrypted(const char* epub_path);
    unsigned long lcp_open_session(const char* epub_path, const char* passphrase);
    void lcp_close_session(unsigned long handle);
    long lcp_session_resource_size(unsigned long handle, const char* path);
    int lcp_session_read_resource(unsigned long handle, const char* path, unsigned long offset, unsigned long length, unsigned char** out_data, unsigned long* out_len);
    void lcp_free_buffer(unsigned char* ptr, unsigned long len);
    const char* lcp_get_error(void);
]]

local function normalizePath(path)
    return path and path:gsub("^/+", "")
end

local OMITTED_LCP_ENTRIES = {
    ["META-INF/encryption.xml"] = true,
    ["META-INF/license.lcpl"] = true,
}

local LcpEntryTransform = {}

function LcpEntryTransform:new(o)
    o = o or {}
    assert(o.file, "LcpEntryTransform requires file")
    assert(o.lib, "LcpEntryTransform requires native library")
    assert(o.session ~= nil and tonumber(o.session) ~= 0, "LcpEntryTransform requires session handle")
    setmetatable(o, self)
    self.__index = self

    o.size_cache = {}
    return o
end

function LcpEntryTransform:decryptedSize(path)
    path = normalizePath(path)
    if path and self.size_cache[path] == nil then
        local size = tonumber(self.lib.lcp_session_resource_size(self.session, path))
        self.size_cache[path] = size and size >= 0 and size or false
    end
    return path and self.size_cache[path] or nil
end

function LcpEntryTransform:readDecryptedEntry(path, size)
    path = normalizePath(path)
    size = tonumber(size)
    if not path or not size then return nil end
    if size == 0 then return "" end

    local out_data = ffi.new("unsigned char*[1]")
    local out_len = ffi.new("unsigned long[1]")
    local rc = self.lib.lcp_session_read_resource(self.session, path, 0, size, out_data, out_len)
    if rc ~= 0 then
        local err = self.lib.lcp_get_error()
        logger.warn("LcpReaderMinimal: resource decrypt failed:", err ~= nil and ffi.string(err) or "unknown error")
        return nil
    end

    local len = tonumber(out_len[0])
    local data = len > 0 and ffi.string(out_data[0], len) or ""
    if out_data[0] ~= nil then
        self.lib.lcp_free_buffer(out_data[0], out_len[0])
    end
    return data
end

function LcpEntryTransform:transformEntry(path)
    path = normalizePath(path)
    if OMITTED_LCP_ENTRIES[path] then return nil end
    local size = self:decryptedSize(path)
    if not size then return nil end
    return self:readDecryptedEntry(path, size)
end

function LcpEntryTransform:close()
    if self.session and tonumber(self.session) ~= 0 then
        self.lib.lcp_close_session(self.session)
    end
    self.session = nil
end

local LcpReaderMinimal = WidgetContainer:extend{
    name = "lcpreader_minimal",
    fullname = _("LCP Reader Minimal"),
    lcp_lib = nil,
}

function LcpReaderMinimal:init()
    -- This plugin is loaded by both FileManager and ReaderUI.
    -- Only set up file interception in FileManager context.
    if self.ui.document then return end

    self.passphrase_cache = G_reader_settings:readSetting(PASSPHRASE_CACHE_KEY, {})

    self:registerDocumentRegistryAuxProvider()
    self:registerDocumentRegistryTransformProvider()
    self:patchFileManagerOpenFile()
end

function LcpReaderMinimal:registerDocumentRegistryAuxProvider()
    DocumentRegistry:addAuxProvider({
        provider_name = self.fullname,
        provider = self.name,
        order = 10,
        disable_file = true,
        disable_type = false,
    })
end

function LcpReaderMinimal:registerDocumentRegistryTransformProvider()
    if DocumentRegistry._lcpreader_minimal_transform_provider then return end

    local self_ref = self
    DocumentRegistry._lcpreader_minimal_transform_provider = function(file, provider)
        if not provider or provider.provider ~= "crengine" then return nil end
        local suffix = file and util.getFileNameSuffix(file)
        if not suffix or suffix:lower() ~= "epub" then return nil end
        if not self_ref:isLcpEncrypted(file) then return nil end

        local passphrase = self_ref.passphrase_cache[file]
        if not passphrase then return nil end
        local transform, err = self_ref:openLcpTransform(file, passphrase)
        if not transform then
            logger.warn("LcpReaderMinimal: cached passphrase transform open failed:", err)
        end
        return transform
    end
    DocumentRegistry:setEpubEntryTransformProvider(DocumentRegistry._lcpreader_minimal_transform_provider)
end

function LcpReaderMinimal:patchFileManagerOpenFile()
    local FileManager = require("apps/filemanager/filemanager")

    if FileManager._lcpreader_minimal_original_openFile then return end
    FileManager._lcpreader_minimal_original_openFile = FileManager.openFile

    local self_ref = self

    function FileManager:openFile(file, provider, doc_caller_callback, aux_caller_callback)
        if not provider then
            local suffix = util.getFileNameSuffix(file)
            if suffix and suffix:lower() == "epub" then
                local is_encrypted = self_ref:isLcpEncrypted(file)
                if is_encrypted then
                    logger.dbg("LcpReaderMinimal: Auto-detected LCP encrypted file:", file)
                    self_ref:openFile(file, true)
                    return
                end
            end
        end
        return FileManager._lcpreader_minimal_original_openFile(self, file, provider, doc_caller_callback, aux_caller_callback)
    end
end

function LcpReaderMinimal:loadLibrary()
    if self.lcp_lib then return self.lcp_lib end

    local extension = ffi.os == "OSX" and ".dylib" or ".so"
    local paths = {
        "plugins/lcpreader-minimal.koplugin/libs/libreadium_lcp" .. extension,
        "libs/libreadium_lcp" .. extension,
        "readium_lcp",
    }

    for _, path in ipairs(paths) do
        local ok, lib = pcall(ffi.load, path)
        if ok then
            local has_session_api = pcall(function() return lib.lcp_open_session end)
            if not has_session_api then
                logger.warn("LcpReaderMinimal: ignoring incompatible LCP library:", path)
            else
                lib.lcp_init()
                self.lcp_lib = lib
                return lib
            end
        end
    end

    return nil
end

function LcpReaderMinimal:isLcpEncrypted(file)
    local lib = self:loadLibrary()
    if not lib then return false end

    local result = lib.lcp_is_encrypted(file)
    if result == 1 then
        return true
    elseif result == 0 then
        return false
    else
        local err = lib.lcp_get_error()
        return false, err ~= nil and ffi.string(err) or "Unknown error"
    end
end

function LcpReaderMinimal:openLcpTransform(file, passphrase)
    local lib = self:loadLibrary()
    if not lib then return nil, "LCP library not found" end

    local session = lib.lcp_open_session(file, passphrase)
    if tonumber(session) == 0 then
        local err = lib.lcp_get_error()
        return nil, err ~= nil and ffi.string(err) or "Unknown error"
    end

    return LcpEntryTransform:new{
        file = file,
        lib = lib,
        session = session,
    }
end

function LcpReaderMinimal:openFile(file, is_encrypted)
    if not self:loadLibrary() then
        UIManager:show(InfoMessage:new{
            text = _("LCP library not found. Please install libreadium_lcp."),
            timeout = 5,
        })
        return
    end

    if is_encrypted == nil then
        local err
        is_encrypted, err = self:isLcpEncrypted(file)
        if err then
            UIManager:show(InfoMessage:new{
                text = T(_("Error checking LCP encryption: %1"), err),
                timeout = 5,
            })
            return
        end
    end

    if not is_encrypted then
        local provider = DocumentRegistry:getProvider(file)
        if provider then
            local ReaderUI = require("apps/reader/readerui")
            ReaderUI:showReader(file, provider)
        end
        return
    end

    local cached_pass = self.passphrase_cache[file]
    if cached_pass then
        self:tryUnlockAndOpen(file, cached_pass)
    else
        self:promptForPassphrase(file)
    end
end

function LcpReaderMinimal:promptForPassphrase(file, retry)
    local title = retry and _("Incorrect passphrase - try again") or _("LCP Protected Content")
    local dialog
    dialog = InputDialog:new{
        title = title,
        description = T(_("Enter your passphrase to unlock:\n%1"), select(2, util.splitFilePathName(file))),
        input_hint = _("Passphrase"),
        text_type = "password",
        buttons = {
            {
                {
                    text = _("Cancel"),
                    id = "close",
                    callback = function()
                        UIManager:close(dialog)
                    end,
                },
                {
                    text = _("Unlock"),
                    is_enter_default = true,
                    callback = function()
                        local passphrase = dialog:getInputText()
                        UIManager:close(dialog)
                        if passphrase and passphrase ~= "" then
                            self:tryUnlockAndOpen(file, passphrase)
                        end
                    end,
                },
            },
        },
    }
    UIManager:show(dialog)
    dialog:onShowKeyboard()
end

function LcpReaderMinimal:tryUnlockAndOpen(file, passphrase)
    local busy = InfoMessage:new{ text = _("Unlocking...") }
    UIManager:show(busy)
    UIManager:forceRePaint()

    local transform, err = self:openLcpTransform(file, passphrase)
    UIManager:close(busy)

    if not transform then
        if err == "Incorrect passphrase" then
            self.passphrase_cache[file] = nil
            G_reader_settings:saveSetting(PASSPHRASE_CACHE_KEY, self.passphrase_cache)
            self:promptForPassphrase(file, true)
        else
            UIManager:show(InfoMessage:new{
                text = T(_("LCP unlock failed: %1"), err),
                timeout = 5,
            })
        end
        return
    end

    self.passphrase_cache[file] = passphrase
    G_reader_settings:saveSetting(PASSPHRASE_CACHE_KEY, self.passphrase_cache)
    transform:close()

    local provider = DocumentRegistry:getProvider(file)
    if provider then
        require("apps/reader/readerui"):showReader(file, provider)
    end
end

function LcpReaderMinimal:isFileTypeSupported(file)
    local suffix = file and util.getFileNameSuffix(file)
    return suffix and suffix:lower() == "epub"
end

return LcpReaderMinimal

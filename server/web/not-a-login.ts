// Attributes that tell password managers (1Password, LastPass, Bitwarden, Dashlane)
// a field holds a secret value, not a login, so they neither fill it nor offer to save it.
export const notALogin = { "data-1p-ignore": "", "data-lpignore": "true", "data-bwignore": "", "data-form-type": "other" };

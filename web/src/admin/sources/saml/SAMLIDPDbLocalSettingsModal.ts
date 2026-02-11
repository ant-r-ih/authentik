// authentik/web/src/admin/providers/saml/SAMLIDPDbLocalSettingsModal.ts
//
// IdP DB local settings editor (INLINE panel version)
//
// Policy:
// - Save => immediate PATCH to DB
// - Cancel/Close => no DB change
// - Emits:
//   - ak-saml-idp-local-settings-saved
//   - ak-saml-idp-local-settings-cancelled
//   - ak-saml-idp-local-settings-closed
//
// Key UI policy (important):
// - No keypair selector in UI
// - ON  => inherit source default behavior (kp_mode="inherit")
// - OFF => force disable for this IdP (kp_mode="none")
// - We do NOT modify *_kp FK here (kept as-is for future "SET" UI).
//
// Notes:
// - This is NOT an overlay modal; it is rendered inline under a row.
// - PF modal header/body/footer styling language to match authentik.

import { AKElement } from "#elements/Base";
import { customElement, property, state } from "lit/decorators.js";
import { html, nothing, type TemplateResult } from "lit";
import { msg } from "@lit/localize";

import "#elements/buttons/SpinnerButton/index";
import "#components/ak-switch-input";

import { showMessage } from "#elements/messages/MessageContainer";
import { MessageLevel } from "#common/messages";
import { DEFAULT_CONFIG } from "#common/api/config";

type KPMode = "inherit" | "set" | "none" | string;

type SavedDetail = {
    idpUuid: string;
    applied: {
        verificationKeyEnabled: boolean;
        encryptionKeyEnabled: boolean;
        signingKeyEnabled: boolean;
    };
};

type PatchLocalSettingsBody = {
    source: number;
    verification_kp_mode?: KPMode;
    encryption_kp_mode?: KPMode;
    signing_kp_mode?: KPMode;
};

async function readErrorBody(res: Response): Promise<string> {
    const ct = res.headers.get("content-type") ?? "";
    try {
        if (ct.includes("application/json")) return JSON.stringify(await res.json());
        return await res.text();
    } catch {
        return await res.text().catch(() => "(failed to read body)");
    }
}

function getCookie(name: string): string | null {
    const m = document.cookie.match(new RegExp("(^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[2]) : null;
}

function getCSRFToken(): string | null {
    return getCookie("authentik_csrf") ?? getCookie("csrftoken");
}

function apiBasePath(): string {
    return (DEFAULT_CONFIG.basePath ?? "/api/v3").replace(/\/$/, "");
}

function enabledToMode(enabled: boolean): KPMode {
    return enabled ? "inherit" : "none";
}

function modeToEnabled(mode: KPMode | null | undefined): boolean {
    if (!mode) return true;
    return String(mode).toLowerCase().trim() !== "none";
}

async function patchSamlidpLocalSettings(
    sourcePk: number,
    idpUuid: string,
    local: {
        verificationKeyEnabled: boolean;
        encryptionKeyEnabled: boolean;
        signingKeyEnabled: boolean;
    },
): Promise<void> {
    const csrf = getCSRFToken();
    if (!csrf) throw new Error("CSRF cookie missing.");

    const url = new URL(
        `${apiBasePath()}/sources/samlidp/${encodeURIComponent(idpUuid)}/`,
        window.location.origin,
    );

    const body: PatchLocalSettingsBody = {
        source: sourcePk,
        verification_kp_mode: enabledToMode(local.verificationKeyEnabled),
        encryption_kp_mode: enabledToMode(local.encryptionKeyEnabled),
        signing_kp_mode: enabledToMode(local.signingKeyEnabled),
    };

    const res = await fetch(url.toString(), {
        method: "PATCH",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
            "X-authentik-CSRF": csrf,
        },
        body: JSON.stringify(body),
    });

    if (!res.ok) {
        throw new Error(`PATCH local settings failed (${res.status}): ${await readErrorBody(res)}`);
    }
}

@customElement("ak-saml-idp-db-local-settings-modal")
export class SAMLIDPDbLocalSettingsModal extends AKElement {
    // ----- controlled by parent -----

    @property({ type: Boolean })
    open = false;

    @property({ type: Boolean })
    disabled = false;

    /** parent "owner" pk: source.pk */
    @property({ type: Number })
    sourcePk = 0;

    @property({ type: String })
    idpUuid = "";

    @property({ type: String })
    rowLabel = "";

    @property({ type: String })
    rowEntityId = "";

    /** DB snapshot fields from parent row */
    @property({ type: String, attribute: false })
    verificationKpMode: KPMode | null = null;

    @property({ type: String, attribute: false })
    encryptionKpMode: KPMode | null = null;

    @property({ type: String, attribute: false })
    signingKpMode: KPMode | null = null;

    // ----- local edit state -----

    @state()
    private saving = false;

    @state()
    private editVerificationKeyEnabled = true;

    @state()
    private editEncryptionKeyEnabled = true;

    @state()
    private editSigningKeyEnabled = true;

    @state()
    private initializedForKey = "";

    protected override updated(changed: Map<string, unknown>): void {
        super.updated(changed);

        const identityKey = `${this.open ? "1" : "0"}:${this.sourcePk}:${this.idpUuid}`;
        const shouldInit =
            this.open &&
            !!this.idpUuid &&
            (changed.has("open") ||
                changed.has("idpUuid") ||
                changed.has("verificationKpMode") ||
                changed.has("encryptionKpMode") ||
                changed.has("signingKpMode"));

        if (!shouldInit) return;
        if (this.initializedForKey === identityKey) return;

        this.editVerificationKeyEnabled = modeToEnabled(this.verificationKpMode);
        this.editEncryptionKeyEnabled = modeToEnabled(this.encryptionKpMode);
        this.editSigningKeyEnabled = modeToEnabled(this.signingKpMode);

        this.initializedForKey = identityKey;
    }

    // ----- event helpers -----

    private emitClosed(): void {
        this.dispatchEvent(
            new CustomEvent("ak-saml-idp-local-settings-closed", { bubbles: true, composed: true }),
        );
    }

    private emitCancelled(): void {
        this.dispatchEvent(
            new CustomEvent("ak-saml-idp-local-settings-cancelled", { bubbles: true, composed: true }),
        );
        this.emitClosed();
    }

    private emitSaved(detail: SavedDetail): void {
        this.dispatchEvent(
            new CustomEvent<SavedDetail>("ak-saml-idp-local-settings-saved", {
                detail,
                bubbles: true,
                composed: true,
            }),
        );
        this.emitClosed();
    }

    private swallow(ev: Event): void {
        ev.preventDefault?.();
        ev.stopPropagation();
    }

    private bubbleOnly(ev: Event): void {
        ev.stopPropagation();
    }

    private onKeydown = (ev: KeyboardEvent): void => {
        if (!this.open) return;
        if (ev.key !== "Escape") return;
        ev.preventDefault();
        ev.stopPropagation();
        if (this.saving) return;
        this.emitCancelled();
    };

    public override connectedCallback(): void {
        super.connectedCallback();
        window.addEventListener("keydown", this.onKeydown, true);
    }

    public override disconnectedCallback(): void {
        window.removeEventListener("keydown", this.onKeydown, true);
        super.disconnectedCallback();
    }

    // ----- actions -----

    private onCancelClick(ev: Event): void {
        ev.preventDefault();
        ev.stopPropagation();
        if (this.saving) return;
        this.emitCancelled();
    }

    private async onSaveClick(ev: Event): Promise<void> {
        ev.preventDefault();
        ev.stopPropagation();

        if (this.saving) return;
        if (this.disabled) return;

        if (!this.sourcePk || !this.idpUuid) {
            showMessage({ level: MessageLevel.error, message: msg("Missing source/IdP identifier.") });
            return;
        }

        const applied = {
            verificationKeyEnabled: !!this.editVerificationKeyEnabled,
            encryptionKeyEnabled: !!this.editEncryptionKeyEnabled,
            signingKeyEnabled: !!this.editSigningKeyEnabled,
        };

        this.saving = true;
        try {
            await patchSamlidpLocalSettings(this.sourcePk, this.idpUuid, applied);
            showMessage({ level: MessageLevel.success, message: msg("Local settings updated.") });
            this.emitSaved({ idpUuid: this.idpUuid, applied });
        } catch (e) {
            // eslint-disable-next-line no-console
            console.error(e);
            showMessage({ level: MessageLevel.error, message: msg("Failed to update local settings.") });
        } finally {
            this.saving = false;
        }
    }

    private renderBody(): TemplateResult {
        const disabled = this.disabled || this.saving;

        return html`
            <section class="pf-c-modal-box" style="box-shadow:none; border:0; padding:0;">
                <header
                    class="pf-c-modal-box__header"
                    style="padding: 0 0 8px 0; border-bottom: 1px solid var(--pf-global--BorderColor--100);"
                >
                    <div style="display:flex; align-items:flex-start; justify-content:space-between; gap: 12px;">
                        <div style="min-width:0;">
                            <h1 class="pf-c-modal-box__title" style="margin:0;">
                                ${this.rowLabel}
                            </h1>
                            <div
                                style="
                                    margin-top: 2px;
                                    font-size: 12px;
                                    opacity: 0.75;
                                    font-family: var(--pf-global--FontFamily--monospace);
                                    word-break: break-all;
                                "
                            >
                                ${this.rowEntityId}
                            </div>
                        </div>

                        <button
                            type="button"
                            class="pf-c-button pf-m-plain"
                            aria-label=${msg("Close")}
                            ?disabled=${disabled}
                            @click=${(e: Event) => this.onCancelClick(e)}
                        >
                            ✕
                        </button>
                    </div>
                </header>

                <div class="pf-c-modal-box__body" style="padding: 10px 0 0 0;">
                    <div class="pf-c-form" @submit=${this.swallow} @ak-form-submit=${this.swallow} @ak-submit=${this.swallow}>
                        <ak-switch-input
                            name="verificationKeyEnabled"
                            label=${msg("Signature verification")}
                            ?checked=${this.editVerificationKeyEnabled}
                            ?disabled=${disabled}
                            @ak-change=${(ev: CustomEvent) => {
                                ev.stopPropagation();
                                const d = ev.detail as any;
                                if (typeof d?.value === "boolean") this.editVerificationKeyEnabled = d.value;
                                else this.editVerificationKeyEnabled = !!(ev.target as HTMLInputElement | null)?.checked;
                            }}
                            @change=${(ev: Event) => {
                                ev.stopPropagation();
                                this.editVerificationKeyEnabled = !!(ev.target as HTMLInputElement | null)?.checked;
                            }}
                        ></ak-switch-input>
                        <p class="pf-c-form__helper-text" style="margin-top: -8px; margin-bottom: 12px;">
                            ${msg("ON uses source default behavior. OFF forces disable for this IdP.")}
                        </p>

                        <ak-switch-input
                            name="encryptionKeyEnabled"
                            label=${msg("Assertion decryption")}
                            ?checked=${this.editEncryptionKeyEnabled}
                            ?disabled=${disabled}
                            @ak-change=${(ev: CustomEvent) => {
                                ev.stopPropagation();
                                const d = ev.detail as any;
                                if (typeof d?.value === "boolean") this.editEncryptionKeyEnabled = d.value;
                                else this.editEncryptionKeyEnabled = !!(ev.target as HTMLInputElement | null)?.checked;
                            }}
                            @change=${(ev: Event) => {
                                ev.stopPropagation();
                                this.editEncryptionKeyEnabled = !!(ev.target as HTMLInputElement | null)?.checked;
                            }}
                        ></ak-switch-input>
                        <p class="pf-c-form__helper-text" style="margin-top: -8px; margin-bottom: 12px;">
                            ${msg("ON uses source default behavior. OFF forces disable for this IdP.")}
                        </p>

                        <ak-switch-input
                            name="signingKeyEnabled"
                            label=${msg("Request signing")}
                            ?checked=${this.editSigningKeyEnabled}
                            ?disabled=${disabled}
                            @ak-change=${(ev: CustomEvent) => {
                                ev.stopPropagation();
                                const d = ev.detail as any;
                                if (typeof d?.value === "boolean") this.editSigningKeyEnabled = d.value;
                                else this.editSigningKeyEnabled = !!(ev.target as HTMLInputElement | null)?.checked;
                            }}
                            @change=${(ev: Event) => {
                                ev.stopPropagation();
                                this.editSigningKeyEnabled = !!(ev.target as HTMLInputElement | null)?.checked;
                            }}
                        ></ak-switch-input>
                        <p class="pf-c-form__helper-text" style="margin-top: -8px;">
                            ${msg("ON uses source default behavior. OFF forces disable for this IdP.")}
                        </p>
                    </div>
                </div>

                <footer class="pf-c-modal-box__footer" style="padding: 12px 0 0 0; border-top: 1px solid var(--pf-global--BorderColor--100);">
                    <div style="display:flex; gap: 10px; justify-content:flex-end;">
                        <ak-spinner-button
                            type="button"
                            class="pf-c-button pf-m-secondary"
                            ?disabled=${disabled}
                            @click=${(e: Event) => this.onCancelClick(e)}
                        >
                            ${msg("Cancel")}
                        </ak-spinner-button>

                        <ak-spinner-button
                            class="pf-c-button pf-m-primary"
                            type="button"
                            ?disabled=${disabled}
                            ?loading=${this.saving}
                            @click=${(e: Event) => void this.onSaveClick(e)}
                        >
                            ${msg("Save")}
                        </ak-spinner-button>
                    </div>
                </footer>
            </section>
        `;
    }

    public override render(): TemplateResult {
        if (!this.open) return nothing;
        return html`${this.renderBody()}`;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-saml-idp-db-local-settings-modal": SAMLIDPDbLocalSettingsModal;
    }
}

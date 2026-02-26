// authentik/web/src/admin/providers/saml/SAMLSPDbLocalSettingsModal.ts
//
// SP DB local settings editor (INLINE panel version)
//
// Policy:
// - Save => immediate PATCH to DB
// - Cancel/Close => no DB change
// - Emits:
//   - ak-saml-sp-local-settings-saved
//   - ak-saml-sp-local-settings-cancelled
//   - ak-saml-sp-local-settings-closed
//
// Key UI policy (important):
// - No keypair selector in UI
// - ON  => inherit provider behavior (override=false)
// - OFF => force disable for this SP (override=true, kp=null)
//
// Notes:
// - This is NOT an overlay modal; it is rendered inline under a row.
// - We still use PF modal header/body/footer visual language to match authentik style.

import { AKElement } from "#elements/Base";
import { customElement, property, state } from "lit/decorators.js";
import { html, nothing, type TemplateResult } from "lit";
import { msg } from "@lit/localize";

import "#elements/buttons/SpinnerButton/index";
import "#elements/ak-dual-select/ak-dual-select-dynamic-selected-provider";
import "#elements/forms/HorizontalFormElement";
import "#components/ak-switch-input";

import { showMessage } from "#elements/messages/MessageContainer";
import { MessageLevel } from "#common/messages";
import { DEFAULT_CONFIG } from "#common/api/config";

import { propertyMappingsProvider, propertyMappingsSelector } from "./SAMLProviderFormHelpers.js";

type SavedDetail = {
    spUuid: string;
    applied: {
        propertyMappingsOverride: boolean;
        propertyMappings: string[];

        // true = inherit provider behavior
        // false = force-disable for this SP
        verificationKeyEnabled: boolean;
        encryptionKeyEnabled: boolean;
        signingKeyEnabled: boolean;
    };
};

type PatchLocalSettingsBody = {
    provider: number;

    property_mappings_override?: boolean;
    property_mappings?: string[];

    verification_kp_override?: boolean;
    encryption_kp_override?: boolean;
    signing_kp_override?: boolean;

    // OFF => disable must explicitly clear local kp
    verification_kp?: string | null;
    encryption_kp?: string | null;
    signing_kp?: string | null;
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

async function patchSamlspLocalSettings(
    providerPk: number,
    spUuid: string,
    localSettings: {
        propertyMappingsOverride: boolean;
        propertyMappings: string[];

        verificationKeyEnabled: boolean;
        encryptionKeyEnabled: boolean;
        signingKeyEnabled: boolean;
    },
): Promise<void> {
    const csrf = getCSRFToken();
    if (!csrf) throw new Error("CSRF cookie missing.");

    const url = new URL(
        `${apiBasePath()}/providers/samlsp/${encodeURIComponent(spUuid)}/`,
        window.location.origin,
    );

    // UI semantics:
    // enabled=true  => override=false (inherit)
    // enabled=false => override=true  (force-disable)
    const verificationOverride = !localSettings.verificationKeyEnabled;
    const encryptionOverride = !localSettings.encryptionKeyEnabled;
    const signingOverride = !localSettings.signingKeyEnabled;

    const body: PatchLocalSettingsBody = {
        provider: providerPk,
        property_mappings_override: localSettings.propertyMappingsOverride,

        verification_kp_override: verificationOverride,
        encryption_kp_override: encryptionOverride,
        signing_kp_override: signingOverride,
    };

    // override=true means "use local setting", and since UI has no selector,
    // local setting is "disabled" => must clear kp explicitly.
    if (verificationOverride) body.verification_kp = null;
    if (encryptionOverride) body.encryption_kp = null;
    if (signingOverride) body.signing_kp = null;

    // override=true のときは空配列も意味があるので送る
    if (localSettings.propertyMappingsOverride) {
        body.property_mappings = (localSettings.propertyMappings ?? []).map(String);
    }

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

@customElement("ak-saml-sp-db-local-settings-modal")
export class SAMLSPDbLocalSettingsModal extends AKElement {
    // ----- controlled by parent -----

    @property({ type: Boolean })
    open = false;

    @property({ type: Boolean })
    disabled = false;

    @property({ type: Number })
    providerPk = 0;

    @property({ type: String })
    spUuid = "";

    @property({ type: String })
    rowLabel = "";

    @property({ type: String })
    rowEntityId = "";

    @property({ type: Boolean })
    propertyMappingsOverride = false;

    @property({ attribute: false })
    propertyMappings: string[] = [];

    // Parent passes these (DB row snapshot). UI uses ON/OFF only.
    // override=false => ON (inherit)
    // override=true  => OFF (force-disable)
    @property({ type: Boolean })
    verificationKpOverride = false;

    @property({ type: Boolean })
    encryptionKpOverride = false;

    @property({ type: Boolean })
    signingKpOverride = false;

    // ----- local edit state -----

    @state()
    private saving = false;

    @state()
    private editPropertyMappingsOverride = false;

    @state()
    private editPropertyMappings: string[] = [];

    // ON/OFF-only UI
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

        const identityKey = `${this.open ? "1" : "0"}:${this.providerPk}:${this.spUuid}`;
        const shouldInit =
            this.open &&
            !!this.spUuid &&
            (changed.has("open") ||
                changed.has("spUuid") ||
                changed.has("propertyMappingsOverride") ||
                changed.has("propertyMappings") ||
                changed.has("verificationKpOverride") ||
                changed.has("encryptionKpOverride") ||
                changed.has("signingKpOverride"));

        if (!shouldInit) return;
        if (this.initializedForKey === identityKey) return;

        this.editPropertyMappingsOverride = !!this.propertyMappingsOverride;
        this.editPropertyMappings = Array.isArray(this.propertyMappings)
            ? this.propertyMappings.map(String)
            : [];

        // override=false => ON (inherit)
        // override=true  => OFF (force-disable)
        this.editVerificationKeyEnabled = !(this.verificationKpOverride ?? false);
        this.editEncryptionKeyEnabled = !(this.encryptionKpOverride ?? false);
        this.editSigningKeyEnabled = !(this.signingKpOverride ?? false);

        this.initializedForKey = identityKey;
    }

    // ----- event helpers -----

    private emitClosed(): void {
        this.dispatchEvent(
            new CustomEvent("ak-saml-sp-local-settings-closed", { bubbles: true, composed: true }),
        );
    }

    private emitCancelled(): void {
        this.dispatchEvent(
            new CustomEvent("ak-saml-sp-local-settings-cancelled", { bubbles: true, composed: true }),
        );
        this.emitClosed();
    }

    private emitSaved(detail: SavedDetail): void {
        this.dispatchEvent(
            new CustomEvent<SavedDetail>("ak-saml-sp-local-settings-saved", {
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

    // ----- dual-select value parsing -----

    private onPropertyMappingsChanged(ev: Event): void {
        ev.stopPropagation();

        const ce = ev as CustomEvent;
        const d = (ce as any)?.detail;

        const pickIds = (arr: unknown[]): string[] =>
            arr
                .map((x) => (Array.isArray(x) ? String(x[0] ?? "") : String(x ?? "")))
                .filter((v) => v.length > 0);

        if (Array.isArray(d?.value)) {
            this.editPropertyMappings = pickIds(d.value);
            return;
        }
        if (Array.isArray(d)) {
            this.editPropertyMappings = pickIds(d);
            return;
        }
        if (Array.isArray(d?.selected)) {
            this.editPropertyMappings = pickIds(d.selected);
        }
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

        if (!this.providerPk || !this.spUuid) {
            showMessage({ level: MessageLevel.error, message: msg("Missing provider/SP identifier.") });
            return;
        }

        const applied = {
            propertyMappingsOverride: !!this.editPropertyMappingsOverride,
            propertyMappings: [...this.editPropertyMappings],

            verificationKeyEnabled: !!this.editVerificationKeyEnabled,
            encryptionKeyEnabled: !!this.editEncryptionKeyEnabled,
            signingKeyEnabled: !!this.editSigningKeyEnabled,
        };

        this.saving = true;
        try {
            await patchSamlspLocalSettings(this.providerPk, this.spUuid, applied);
            showMessage({ level: MessageLevel.success, message: msg("Local settings updated.") });
            this.emitSaved({ spUuid: this.spUuid, applied });
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
                    <div
                        class="pf-c-form"
                        @submit=${this.swallow}
                        @ak-form-submit=${this.swallow}
                        @ak-submit=${this.swallow}
                    >
                        <ak-switch-input
                            name="propertyMappingsOverride"
                            label=${msg("Property mappings override")}
                            ?checked=${this.editPropertyMappingsOverride}
                            ?disabled=${disabled}
                            @ak-change=${(ev: CustomEvent) => {
                                ev.stopPropagation();
                                const d = ev.detail as any;
                                if (typeof d?.value === "boolean") {
                                    this.editPropertyMappingsOverride = d.value;
                                    return;
                                }
                                this.editPropertyMappingsOverride = !!(ev.target as HTMLInputElement | null)?.checked;
                            }}
                            @change=${(ev: Event) => {
                                ev.stopPropagation();
                                this.editPropertyMappingsOverride = !!(ev.target as HTMLInputElement | null)?.checked;
                            }}
                        ></ak-switch-input>

                        ${this.editPropertyMappingsOverride
                            ? html`
                                  <ak-form-element-horizontal label=${msg("Property mappings")} name="propertyMappings">
                                      <div
                                          @submit=${this.swallow}
                                          @ak-form-submit=${this.swallow}
                                          @ak-submit=${this.swallow}
                                          @click=${this.bubbleOnly}
                                          @mousedown=${this.bubbleOnly}
                                          @mouseup=${this.bubbleOnly}
                                          @keydown=${this.bubbleOnly}
                                      >
                                          <ak-dual-select-dynamic-selected
                                              .provider=${propertyMappingsProvider}
                                              .selector=${propertyMappingsSelector(this.editPropertyMappings)}
                                              available-label=${msg("Available User Property Mappings")}
                                              selected-label=${msg("Selected User Property Mappings")}
                                              @ak-dual-select-change=${(ev: Event) => this.onPropertyMappingsChanged(ev)}
                                              @ak-change=${(ev: Event) => this.onPropertyMappingsChanged(ev)}
                                              @change=${(ev: Event) => this.onPropertyMappingsChanged(ev)}
                                          ></ak-dual-select-dynamic-selected>
                                      </div>

                                      <p class="pf-c-form__helper-text">
                                          ${msg("These mappings are applied only to this existing SP when override is enabled.")}
                                      </p>
                                  </ak-form-element-horizontal>
                              `
                            : nothing}

                        <hr style="margin: 16px 0; border: 0; border-top: 1px solid var(--pf-global--BorderColor--100);" />

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
                            ${msg("ON uses provider default behavior (automatic if configured). OFF forces disable for this SP.")}
                        </p>

                        <ak-switch-input
                            name="encryptionKeyEnabled"
                            label=${msg("Assertion encryption")}
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
                            ${msg("ON uses provider default behavior (automatic if configured). OFF forces disable for this SP.")}
                        </p>

                        <ak-switch-input
                            name="signingKeyEnabled"
                            label=${msg("Response signing")}
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
                            ${msg("ON uses provider default behavior (automatic if configured). OFF forces disable for this SP.")}
                        </p>
                    </div>
                </div>

                <footer
                    class="pf-c-modal-box__footer"
                    style="padding: 12px 0 0 0; border-top: 1px solid var(--pf-global--BorderColor--100);"
                >
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
        "ak-saml-sp-db-local-settings-modal": SAMLSPDbLocalSettingsModal;
    }
}

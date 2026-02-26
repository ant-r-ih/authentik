import { customElement, property, state } from "lit/decorators.js";
import { html } from "lit";
import { msg } from "@lit/localize";

import { AKElement } from "#elements/Base";
import "#elements/ak-dual-select/ak-dual-select";
import "#elements/forms/ModalForm";
import "#elements/buttons/SpinnerButton/index";
import "#admin/providers/saml/SAMLSPSnapshotImport";

import { showMessage } from "#elements/messages/MessageContainer";
import { MessageLevel } from "#common/messages";
import { DEFAULT_CONFIG } from "#common/api/config";

import { ProvidersApi, type SAMLProvider, type SAMLSP } from "@goauthentik/api";
import type { DualSelectPair } from "#elements/ak-dual-select/types";


// function getCookie(name: string): string | null {
//   const m = document.cookie.match(new RegExp("(^|; )" + name + "=([^;]*)"));
//   return m ? decodeURIComponent(m[2]) : null;
// }

// function getCSRFToken(): string | null {
//     return getCookie("authentik_csrf") ?? getCookie("csrftoken");
// }

// async function catalogPreviewSP(providerPk: string, file: File): Promise<unknown[]> {
//     const basePath = (DEFAULT_CONFIG.basePath ?? "/api/v3").replace(/\/$/, "");
//     const url = new URL(`${basePath}/providers/saml/catalog/preview/`, window.location.origin);
//     url.searchParams.set("provider", String(providerPk));
//     url.searchParams.set("kind", "sp");

//     const form = new FormData();
//     form.append("file", file, file.name);

//     const csrf = getCookie("authentik_csrf");
//     if (!csrf) throw new Error("authentik_csrf cookie missing.");

//     const res = await fetch(url.toString(), {
//         method: "POST",
//         body: form,
//         credentials: "include",
//         headers: {
//             "X-authentik-CSRF": csrf,
//         },
//     });

//     const rawText = await res.text();
//     if (!res.ok) throw new Error(`Catalog preview failed (${res.status}): ${rawText}`);

//     const data = JSON.parse(rawText);
//     if (!Array.isArray(data)) throw new Error("Catalog preview response is not a list");
//     return data;
// }

@customElement("ak-provider-saml-sp-tab")
export class SAMLProviderSPTab extends AKElement {
    @property({ attribute: false })
    provider!: SAMLProvider;

    @state()
    sps: SAMLSP[] = [];

    @state()
    selected: DualSelectPair[] = [];

    @state()
    loading = true;

    @state()
    saving = false;

    @state()
    originalEnabled: string[] = [];

    @state()
    search = "";

    async connectedCallback() {
        super.connectedCallback();
        await this.fetchSPs();
    }

    async fetchSPs() {
        if (!this.provider?.pk) return;

        const api = new ProvidersApi(DEFAULT_CONFIG);

        const all: SAMLSP[] = [];
        let page = 1;

        for (;;) {
            const res = await api.providersSamlspList({
                provider: this.provider.pk,
                pageSize: 100, // サーバ側が上限100っぽいので合わせる（1000でも結果は同じ）
                page,
            });

            all.push(...(res.results ?? []));

            // v3 の list は pagination.next が返る想定
            const next = (res as any).pagination?.next as number | null | undefined;
            if (!next) break;

            page = next;
        }

        this.sps = all;

        this.originalEnabled = this.sps
            .filter((sp) => sp.enabled)
            .map((sp) => sp.uuid);

        this.selected = this.sps
            .filter((sp) => sp.enabled)
            .map((sp) => this.toPair(sp));

        this.loading = false;
    }

    toPair(sp: SAMLSP): DualSelectPair {
        return [
            sp.uuid,
            html`
                <div>
                    <div><strong>${sp.name}</strong></div>
                    <div style="font-size: 12px; opacity: 0.7;">
                        ${sp.entityId}
                    </div>
                </div>
            `,
            `${sp.name} ${sp.entityId}`.toLowerCase(),  // ← comparator 🔥
        ];
    }

    get available(): DualSelectPair[] {
        const q = (this.search ?? "").toLowerCase();

        return this.sps
            .filter((sp) => {
                if (!q) return true;

                const name = sp.name ?? "";
                const entityId = sp.entityId ?? "";

                return (
                    name.toLowerCase().includes(q) ||
                    entityId.toLowerCase().includes(q)
                );
            })
            .map((sp) => this.toPair(sp));
    }

    get dirty(): boolean {
        const current = this.selected.map(([uuid]) => String(uuid)).sort();
        const original = [...this.originalEnabled].sort();

        return JSON.stringify(current) !== JSON.stringify(original);
    }

    async save() {
        if (!this.dirty) return;

        this.saving = true;

        const api = new ProvidersApi(DEFAULT_CONFIG);

        try {
            await api.providersSamlspSetEnabledCreate({
                sAMLSPRequest: {
                    provider: this.provider.pk,
                    enabled: this.selected.map(([uuid]) => uuid),
                },
            });

            this.originalEnabled = this.selected.map(([uuid]) => String(uuid));

            showMessage({
                level: MessageLevel.success,
                message: msg("Service Providers updated successfully."),
            });
        } catch (err) {
            console.error(err);

            showMessage({
                level: MessageLevel.error,
                message: msg("Failed to update Service Providers."),
            });
        } finally {
            this.saving = false;
        }
    }

    render() {
        if (this.loading) {
            return html`<p>${msg("Loading Service Providers...")}</p>`;
        }

        return html`
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 12px;">
                <ak-forms-modal>
                    <span slot="header">${msg("Manage from metadata")}</span>
                    <span slot="submit">${msg("Save")}</span>

<ak-saml-snapshot-import
  slot="form"
  kind="sp"
  .ownerPk=${this.provider.pk}
 @ak-import-finished=${async (ev: Event) => {
     ev.stopPropagation();
     // dual-list を最新化
     this.loading = true;
     try {
         await this.fetchSPs();
     } finally {
         this.loading = false;
     }
}}
></ak-saml-snapshot-import>

                    <!-- Use authentik's standard button component for modal trigger -->
                    <ak-spinner-button
                        slot="trigger"
                        class="pf-m-secondary"
                        type="button"
                    >
                        ${msg("Import")}
                    </ak-spinner-button>
                </ak-forms-modal>

                <ak-spinner-button
                    class=${this.dirty ? "pf-m-primary" : "pf-m-secondary"}
                    ?disabled=${!this.dirty || this.saving}
                    ?loading=${this.saving}
                    @click=${this.save}
                >
                    ${msg("Save")}
                </ak-spinner-button>
            </div>

            ${this.sps.length === 0
                ? html`<p>${msg("No Service Providers found.")}</p>`
                : html`
                    <ak-dual-select
                        .options=${this.available}
                        .selected=${this.selected}
                        available-label=${msg("Disabled")}
                        selected-label=${msg("Enabled")}
                        @ak-dual-select-change=${(ev: CustomEvent) => {
                            this.selected = ev.detail.value;
                        }}
                        @ak-dual-select-search=${(ev: CustomEvent<string>) => {
                            this.search = ev.detail ?? "";
                        }}
                    ></ak-dual-select>
                `}
        `;
    }
}

type CatalogState = "unknown" | "new" | "unchanged" | "updated";

type SAMLMetadataCatalogItem = {
    entity_id: string;
    kind: string[];
    display_name?: string | null;
    from_aggregate?: boolean;
    container_name_chain?: string[];
    sp?: {
        acs?: Array<{ binding?: string; location?: string; index?: string; is_default?: boolean }>;
        sls?: Array<{ binding?: string; location?: string }>;
        authn_requests_signed?: boolean;
        want_assertions_signed?: boolean;
        name_id_formats?: string[];
    } | null;
    idp?: unknown | null;
    certs?: { signing?: number; encryption?: number; unspecified?: number };
    states?: {
        metadata?: CatalogState;
        metadata_hash?: string;
    };
};

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

import { SourcesApi, type SAMLSource, type SAMLIDP } from "@goauthentik/api";
import type { DualSelectPair } from "#elements/ak-dual-select/types";

@customElement("ak-source-saml-idp-tab")
export class SAMLSourceIDPTab extends AKElement {
    @property({ attribute: false })
    source!: SAMLSource;

    @state()
    idps: SAMLIDP[] = [];

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
        await this.fetchIDPs();
    }

    async fetchIDPs() {
        if (!this.source?.pk) return;

        const api = new SourcesApi(DEFAULT_CONFIG);

        const all: SAMLIDP[] = [];
        let page = 1;

        for (;;) {
            const res = await api.sourcesSamlidpList({
                source: this.source.pk,
                pageSize: 100,
                page,
            });
            all.push(...(res.results ?? []));

            const next = (res as any).pagination?.next as number | null | undefined;
            if (!next) break;
            page = next;
        }

        this.idps = all;

        this.originalEnabled = this.idps.filter((x) => x.enabled).map((x) => x.uuid);

        this.selected = this.idps
            .filter((x) => x.enabled)
            .map((x) => this.toPair(x));

        this.loading = false;
    }

    toPair(idp: SAMLIDP): DualSelectPair {
        const entityId = (idp.entityId ?? idp.entity_id ?? "") as string;
        const name = (idp.name ?? "") as string;

        return [
            idp.uuid,
            html`
                <div>
                    <div><strong>${name || entityId}</strong></div>
                    <div style="font-size: 12px; opacity: 0.7;">${entityId}</div>
                </div>
            `,
            `${name} ${entityId}`.toLowerCase(),
        ];
    }

    get available(): DualSelectPair[] {
        const q = (this.search ?? "").toLowerCase();
        return this.idps
            .filter((idp) => {
                if (!q) return true;
                const name = (idp.name ?? "").toLowerCase();
                const entityId = ((idp.entityId ?? idp.entity_id ?? "") as string).toLowerCase();
                return name.includes(q) || entityId.includes(q);
            })
            .map((idp) => this.toPair(idp));
    }

    get dirty(): boolean {
        const current = this.selected.map(([uuid]) => String(uuid)).sort();
        const original = [...this.originalEnabled].sort();
        return JSON.stringify(current) !== JSON.stringify(original);
    }

    async save() {
        if (!this.dirty) return;

        this.saving = true;
        const api = new SourcesApi(DEFAULT_CONFIG);

        try {
            await api.sourcesSamlidpSetEnabledCreate({
                setEnabledSerializerRequest: {
                    source: this.source.pk,
                    enabled: this.selected.map(([uuid]) => uuid),
                },
            });

            this.originalEnabled = this.selected.map(([uuid]) => String(uuid));

            showMessage({ level: MessageLevel.success, message: msg("Identity Providers updated successfully.") });
        } catch (err) {
            // eslint-disable-next-line no-console
            console.error(err);
            showMessage({ level: MessageLevel.error, message: msg("Failed to update Identity Providers.") });
        } finally {
            this.saving = false;
        }
    }

    render() {
        if (this.loading) {
            return html`<p>${msg("Loading Identity Providers...")}</p>`;
        }

        return html`
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 12px;">
                <ak-forms-modal>
                    <span slot="header">${msg("Manage from metadata")}</span>
                    <span slot="submit">${msg("Save")}</span>

                    <ak-saml-snapshot-import
                        slot="form"
                        kind="idp"
                        .ownerPk=${this.source.pk}
                        .ownerLabel=${this.source.name}
                        @ak-import-finished=${() => this.fetchIDPs()}
                    ></ak-saml-snapshot-import>

                    <ak-spinner-button slot="trigger" class="pf-m-secondary" type="button">
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

            ${this.idps.length === 0
                ? html`<p>${msg("No Identity Providers found.")}</p>`
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

import "#admin/common/ak-crypto-certificate-search";
import "#admin/common/ak-crypto-keyring-manager-form";
import "#components/ak-radio-input";
import "#components/ak-file-search-input";
import "#components/ak-switch-input";
import "#elements/ak-dual-select/ak-dual-select-dynamic-selected-provider";
import "#elements/buttons/SpinnerButton/index";
import "#elements/forms/HorizontalFormElement";
import "#elements/forms/ModalForm";

import { propertyMappingsProvider, propertyMappingsSelector } from "./SAMLProviderFormHelpers.js";

import { aki } from "#common/api/client";
import { PFSize } from "#common/enums";
import { isResponseErrorLike } from "#common/errors/network";
import { MessageLevel } from "#common/messages";

import { DualSelectPair } from "#elements/ak-dual-select/types";
import { AKElement } from "#elements/Base";
import { showMessage } from "#elements/messages/MessageContainer";

import {
    ApplyPolicyEnum,
    InputModeEnum,
    ProvidersApi,
    SAMLBindingsEnum,
    SAMLNameIDPolicyEnum,
    SAMLProvider,
    SAMLSP,
    SAMLSPApplyResponse,
    SAMLSPPreviewItem,
    UsageEnum,
} from "@goauthentik/api";

import { msg } from "@lit/localize";
import { CSSResult, html, nothing, PropertyValues, TemplateResult } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import PFBackdrop from "@patternfly/patternfly/components/Backdrop/backdrop.css";
import PFButton from "@patternfly/patternfly/components/Button/button.css";
import PFForm from "@patternfly/patternfly/components/Form/form.css";
import PFFormControl from "@patternfly/patternfly/components/FormControl/form-control.css";
import PFLabel from "@patternfly/patternfly/components/Label/label.css";
import PFList from "@patternfly/patternfly/components/List/list.css";
import PFModalBox from "@patternfly/patternfly/components/ModalBox/modal-box.css";
import PFSwitch from "@patternfly/patternfly/components/Switch/switch.css";
import PFTable from "@patternfly/patternfly/components/Table/table.css";
import PFTitle from "@patternfly/patternfly/components/Title/title.css";
import PFBullseye from "@patternfly/patternfly/layouts/Bullseye/bullseye.css";

type PreviewRow = {
    item: SAMLSPPreviewItem;
    selected: boolean;
};

type KeyMode = "kp" | "ring";

const keyModeOptions = [
    { label: msg("Single keypair"), value: "kp", default: true },
    { label: msg("Key ring"), value: "ring" },
];

@customElement("ak-provider-saml-sp-tab")
export class SAMLProviderSPTab extends AKElement {
    @property({ attribute: false })
    parent?: SAMLProvider;

    @state()
    currentSPs: SAMLSP[] = [];

    @state()
    currentSearch = "";

    @state()
    selectedCurrentSPUuids: string[] = [];

    @state()
    previewRows: PreviewRow[] = [];

    @state()
    previewSearch = "";

    @state()
    fileRef = "";

    @state()
    signingCertificate?: string;

    @state()
    applyPolicy: ApplyPolicyEnum = ApplyPolicyEnum.IfNotDeviated;

    @state()
    createMissingRings = true;

    @state()
    loadingCurrent = false;

    @state()
    previewLoading = false;

    @state()
    applyLoading = false;

    @state()
    applyResult?: SAMLSPApplyResponse;

    @state()
    updatingSPUuid?: string;

    @state()
    importModalOpen = false;

    @state()
    editingSP?: SAMLSP;

    @state()
    editSaving = false;

    @state()
    openingEditUuid?: string;

    @state()
    editEnabled = true;

    @state()
    editAcsUrl = "";

    @state()
    editSpBinding: SAMLBindingsEnum = SAMLBindingsEnum.Post;

    @state()
    editSlsUrl = "";

    @state()
    editSlsBinding: SAMLBindingsEnum = SAMLBindingsEnum.Redirect;

    @state()
    editNameIdPolicy: SAMLNameIDPolicyEnum =
        SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml11NameidFormatUnspecified;

    @state()
    editAuthnRequestsSigned = false;

    @state()
    editWantAssertionsSigned = false;

    @state()
    editVerificationKp?: string;

    @state()
    editSigningKp?: string;

    @state()
    editEncryptionKp?: string;

    @state()
    editVerificationKpRing = "";

    @state()
    editSigningKpRing = "";

    @state()
    editEncryptionKpRing = "";

    @state()
    editVerificationKeyMode: KeyMode = "kp";

    @state()
    editSigningKeyMode: KeyMode = "kp";

    @state()
    editEncryptionKeyMode: KeyMode = "kp";

    @state()
    editVerificationKpOverride = false;

    @state()
    editSigningKpOverride = false;

    @state()
    editEncryptionKpOverride = false;

    @state()
    editFreezeVerificationKp = false;

    @state()
    editFreezeSigningKp = false;

    @state()
    editFreezeEncryptionKp = false;

    @state()
    editLocalOverrideSet = false;

    @state()
    editPropertyMappingsOverride = false;

    @state()
    editPropertyMappings: string[] = [];

    @state()
    deletingSPs: SAMLSP[] = [];

    @state()
    deleteLoading = false;

    static styles: CSSResult[] = [
        PFBackdrop,
        PFButton,
        PFForm,
        PFFormControl,
        PFLabel,
        PFList,
        PFModalBox,
        PFSwitch,
        PFTable,
        PFTitle,
        PFBullseye,
    ];

    protected updated(changedProperties: PropertyValues<this>): void {
        if (!changedProperties.has("parent")) {
            return;
        }
        if (!this.parent?.pk) {
            return;
        }
        this.fetchCurrentSPs();
    }

    private async fetchCurrentSPs(): Promise<void> {
        if (!this.parent?.pk) {
            this.currentSPs = [];
            return;
        }
        this.loadingCurrent = true;
        const api = aki(ProvidersApi);

        try {
            const all: SAMLSP[] = [];
            let page = 1;

            for (;;) {
                const response = await api.providersSamlServiceProvidersList({
                    id: this.parent.pk,
                    page,
                    pageSize: 100,
                });
                const rows = Array.isArray(response.results) ? response.results : [];
                all.push(...rows);

                if (response.pagination.current >= response.pagination.totalPages) {
                    break;
                }
                page += 1;
            }

            this.currentSPs = all;
            const availableUuids = new Set(
                all
                    .map((entry) => entry.uuid)
                    .filter((entryUuid): entryUuid is string => Boolean(entryUuid)),
            );
            this.selectedCurrentSPUuids = this.selectedCurrentSPUuids.filter((entryUuid) =>
                availableUuids.has(entryUuid),
            );
        } catch (error) {
            if (isResponseErrorLike(error) && error.response.status === 404) {
                this.currentSPs = [];
                this.selectedCurrentSPUuids = [];
                return;
            }
            showMessage({
                level: MessageLevel.error,
                message: msg("Failed to load Service Providers."),
                description: String(error),
            });
        } finally {
            this.loadingCurrent = false;
        }
    }

    private onFileRefChange(event: CustomEvent<{ value?: { name?: string } | null }>): void {
        const selected = event.detail?.value;
        this.fileRef = selected?.name ?? "";
    }

    private onSigningCertificateInput(event: Event): void {
        const target = event.currentTarget as { value?: string | null };
        this.signingCertificate = target.value ?? undefined;
    }

    private isChanged(item: SAMLSPPreviewItem): boolean {
        return !item.compare._exists || item.compare.runtimeChanged || item.compare.certChanged;
    }

    private compareStateLabel(item: SAMLSPPreviewItem): string {
        if (!item.compare._exists) {
            return msg("NEW");
        }
        if (item.compare.runtimeChanged || item.compare.certChanged) {
            return msg("UPDATED");
        }
        return msg("UNCHANGED");
    }

    private compareStateVariant(item: SAMLSPPreviewItem): "green" | "blue" | "grey" {
        if (!item.compare._exists) {
            return "green";
        }
        if (item.compare.runtimeChanged || item.compare.certChanged) {
            return "blue";
        }
        return "grey";
    }

    private hasSelectedPreviewRows(): boolean {
        return this.previewRows.some((row) => row.selected);
    }

    private areAllPreviewRowsSelected(): boolean {
        return this.previewRows.length > 0 && this.previewRows.every((row) => row.selected);
    }

    private setAllPreviewRows(selected: boolean): void {
        this.previewRows = this.previewRows.map((row) => ({ ...row, selected }));
    }

    private getDisplayNameForItem(item: SAMLSPPreviewItem): string {
        return (item.metadata.displayName || "").trim() || item.metadata.entityId;
    }

    private getSnapshotDisplayName(sp: SAMLSP): string {
        const snapshot = sp.metadataSnapshot;
        if (!snapshot || typeof snapshot !== "object") {
            return "";
        }
        const snapshotRecord = snapshot as { runtime?: unknown; display_name?: unknown };
        const runtime = snapshotRecord.runtime;
        if (runtime && typeof runtime === "object") {
            const runtimeName = (runtime as { display_name?: unknown }).display_name;
            if (typeof runtimeName === "string") {
                return runtimeName.trim();
            }
        }
        const snapshotName = snapshotRecord.display_name;
        if (typeof snapshotName === "string") {
            return snapshotName.trim();
        }
        return "";
    }

    private getDisplayNameForSP(sp: SAMLSP): string {
        return (sp.name || "").trim() || this.getSnapshotDisplayName(sp) || sp.entityId;
    }

    private getDescriptorForItem(item: SAMLSPPreviewItem): string {
        return item.metadata.entityId;
    }

    private getDescriptorForSP(sp: SAMLSP): string {
        return sp.entityId;
    }

    private getFilteredPreviewRows(): PreviewRow[] {
        const query = this.previewSearch.trim().toLowerCase();
        if (!query) {
            return this.previewRows;
        }

        return this.previewRows.filter((row) => {
            const displayName = this.getDisplayNameForItem(row.item);
            const descriptor = this.getDescriptorForItem(row.item);
            return (
                row.item.metadata.entityId.toLowerCase().includes(query) ||
                displayName.toLowerCase().includes(query) ||
                descriptor.toLowerCase().includes(query)
            );
        });
    }

    private getFilteredCurrentSPs(): SAMLSP[] {
        const query = this.currentSearch.trim().toLowerCase();
        if (!query) {
            return this.currentSPs;
        }

        return this.currentSPs.filter((sp) => {
            const displayName = this.getDisplayNameForSP(sp);
            const descriptor = this.getDescriptorForSP(sp);
            return (
                sp.entityId.toLowerCase().includes(query) ||
                displayName.toLowerCase().includes(query) ||
                descriptor.toLowerCase().includes(query)
            );
        });
    }

    private openImportModal(): void {
        this.importModalOpen = true;
    }

    private closeImportModal(): void {
        this.importModalOpen = false;
    }

    private normalizeBindingToken(
        value: string | undefined,
        fallback: SAMLBindingsEnum,
    ): SAMLBindingsEnum {
        const token = (value || "").trim().toLowerCase();
        if (token === SAMLBindingsEnum.Redirect || token.endsWith("http-redirect")) {
            return SAMLBindingsEnum.Redirect;
        }
        if (token === SAMLBindingsEnum.Post || token.endsWith("http-post")) {
            return SAMLBindingsEnum.Post;
        }
        return fallback;
    }

    private normalizeNameIdPolicy(value: string | undefined): SAMLNameIDPolicyEnum {
        const normalized = (value || "").trim().toLowerCase();
        const candidates = Object.values(SAMLNameIDPolicyEnum) as SAMLNameIDPolicyEnum[];
        const matched = candidates.find((candidate) => candidate.toLowerCase() === normalized);
        return matched || SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml11NameidFormatUnspecified;
    }

    private applyEditingState(sp: SAMLSP): void {
        this.editingSP = sp;
        this.editEnabled = Boolean(sp.enabled);
        this.editAcsUrl = sp.acsUrl || "";
        this.editSpBinding = this.normalizeBindingToken(sp.spBinding, SAMLBindingsEnum.Post);
        this.editSlsUrl = sp.slsUrl || "";
        this.editSlsBinding = this.normalizeBindingToken(sp.slsBinding, SAMLBindingsEnum.Redirect);
        this.editNameIdPolicy = this.normalizeNameIdPolicy(sp.nameIdPolicy);
        this.editAuthnRequestsSigned = Boolean(sp.authnRequestsSigned);
        this.editWantAssertionsSigned = Boolean(sp.wantAssertionsSigned);
        this.editVerificationKp = sp.verificationKp || undefined;
        this.editSigningKp = sp.signingKp || undefined;
        this.editEncryptionKp = sp.encryptionKp || undefined;
        this.editVerificationKpRing = sp.verificationKpRing || "";
        this.editSigningKpRing = sp.signingKpRing || "";
        this.editEncryptionKpRing = sp.encryptionKpRing || "";
        this.editVerificationKeyMode = sp.verificationKp
            ? "kp"
            : sp.verificationKpRing
              ? "ring"
              : "kp";
        this.editSigningKeyMode = sp.signingKp ? "kp" : sp.signingKpRing ? "ring" : "kp";
        this.editEncryptionKeyMode = sp.encryptionKp ? "kp" : sp.encryptionKpRing ? "ring" : "kp";
        this.editVerificationKpOverride = Boolean(sp.verificationKpOverride);
        this.editSigningKpOverride = Boolean(sp.signingKpOverride);
        this.editEncryptionKpOverride = Boolean(sp.encryptionKpOverride);
        this.editFreezeVerificationKp = Boolean(sp.freezeVerificationKp);
        this.editFreezeSigningKp = Boolean(sp.freezeSigningKp);
        this.editFreezeEncryptionKp = Boolean(sp.freezeEncryptionKp);
        this.editLocalOverrideSet = Boolean(sp.localOverrideSet);
        this.editPropertyMappingsOverride = Boolean(sp.propertyMappingsOverride);
        this.editPropertyMappings = Array.isArray(sp.propertyMappings) ? sp.propertyMappings : [];
    }

    private async openEditModal(sp: SAMLSP): Promise<void> {
        if (!this.parent?.pk || !sp.uuid) {
            return;
        }
        this.openingEditUuid = sp.uuid;
        try {
            const fresh = await aki(ProvidersApi).providersSamlServiceProvidersRetrieve({
                id: this.parent.pk,
                spId: sp.uuid,
            });
            this.applyEditingState(fresh);
        } catch (error) {
            showMessage({
                level: MessageLevel.error,
                message: msg("Failed to load Service Provider settings."),
                description: String(error),
            });
        } finally {
            this.openingEditUuid = undefined;
        }
    }

    private closeEditModal(): void {
        this.editingSP = undefined;
        this.editSaving = false;
        this.openingEditUuid = undefined;
    }

    private openDeleteModal(sp: SAMLSP): void {
        this.deletingSPs = [sp];
    }

    private openBulkDeleteModal(): void {
        const selected = this.currentSPs.filter(
            (sp) => !!sp.uuid && this.selectedCurrentSPUuids.includes(sp.uuid),
        );
        if (selected.length < 1) {
            showMessage({
                level: MessageLevel.warning,
                message: msg("Select at least one Service Provider."),
            });
            return;
        }
        this.deletingSPs = selected;
    }

    private closeDeleteModal(): void {
        this.deletingSPs = [];
        this.deleteLoading = false;
    }

    private isCurrentRowSelected(sp: SAMLSP): boolean {
        if (!sp.uuid) {
            return false;
        }
        return this.selectedCurrentSPUuids.includes(sp.uuid);
    }

    private setCurrentRowSelected(sp: SAMLSP, selected: boolean): void {
        if (!sp.uuid) {
            return;
        }
        if (selected) {
            if (this.selectedCurrentSPUuids.includes(sp.uuid)) {
                return;
            }
            this.selectedCurrentSPUuids = [...this.selectedCurrentSPUuids, sp.uuid];
            return;
        }
        this.selectedCurrentSPUuids = this.selectedCurrentSPUuids.filter(
            (entryUuid) => entryUuid !== sp.uuid,
        );
    }

    private areAllCurrentRowsSelected(rows: SAMLSP[]): boolean {
        const rowUuids = rows
            .map((sp) => sp.uuid)
            .filter((entryUuid): entryUuid is string => Boolean(entryUuid));
        return (
            rowUuids.length > 0 &&
            rowUuids.every((entryUuid) => this.selectedCurrentSPUuids.includes(entryUuid))
        );
    }

    private setAllCurrentRowsSelected(rows: SAMLSP[], selected: boolean): void {
        const rowUuids = rows
            .map((sp) => sp.uuid)
            .filter((entryUuid): entryUuid is string => Boolean(entryUuid));
        if (selected) {
            this.selectedCurrentSPUuids = Array.from(
                new Set([...this.selectedCurrentSPUuids, ...rowUuids]),
            );
            return;
        }
        this.selectedCurrentSPUuids = this.selectedCurrentSPUuids.filter(
            (entryUuid) => !rowUuids.includes(entryUuid),
        );
    }

    private async previewFromFile(): Promise<void> {
        if (!this.parent?.pk) {
            return;
        }
        if (!this.fileRef) {
            showMessage({
                level: MessageLevel.warning,
                message: msg("Select metadata file first."),
            });
            return;
        }

        this.previewLoading = true;
        this.applyResult = undefined;

        try {
            const response = await aki(ProvidersApi).providersSamlServiceProvidersPreviewCreate({
                id: this.parent.pk,
                sAMLSPPreviewRequest: {
                    inputMode: InputModeEnum.File,
                    fileRef: this.fileRef,
                    signingCertificate: this.signingCertificate,
                },
            });

            const results = Array.isArray(response.results) ? response.results : [];
            this.previewRows = results.map((item) => ({
                item,
                selected: this.isChanged(item),
            }));

            showMessage({
                level: MessageLevel.info,
                message: msg("Preview loaded."),
            });
        } catch (error) {
            showMessage({
                level: MessageLevel.error,
                message: msg("Failed to preview metadata."),
                description: String(error),
            });
        } finally {
            this.previewLoading = false;
        }
    }

    private async applySelected(): Promise<void> {
        if (!this.parent?.pk) {
            return;
        }

        const selectedEntityIds = this.previewRows
            .filter((row) => row.selected)
            .map((row) => row.item.metadata.entityId);

        if (selectedEntityIds.length < 1) {
            showMessage({
                level: MessageLevel.warning,
                message: msg("Select at least one entity."),
            });
            return;
        }

        this.applyLoading = true;

        try {
            const response = await aki(ProvidersApi).providersSamlServiceProvidersApplyCreate({
                id: this.parent.pk,
                sAMLSPApplyRequest: {
                    inputMode: InputModeEnum.File,
                    fileRef: this.fileRef,
                    signingCertificate: this.signingCertificate,
                    entityIds: selectedEntityIds,
                    applyPolicy: this.applyPolicy,
                    createMissingRings: this.createMissingRings,
                },
            });

            this.applyResult = response;
            await this.fetchCurrentSPs();

            showMessage({
                level: MessageLevel.success,
                message: msg("Metadata apply completed."),
            });
        } catch (error) {
            showMessage({
                level: MessageLevel.error,
                message: msg("Failed to apply metadata."),
                description: String(error),
            });
        } finally {
            this.applyLoading = false;
        }
    }

    private async updateSPEnabled(sp: SAMLSP, enabled: boolean): Promise<void> {
        if (!this.parent?.pk || !sp.uuid) {
            return;
        }
        this.updatingSPUuid = sp.uuid;

        try {
            await aki(ProvidersApi).providersSamlServiceProvidersPartialUpdate({
                id: this.parent.pk,
                spId: sp.uuid,
                patchedSAMLSPRequest: {
                    enabled,
                },
            });

            this.currentSPs = this.currentSPs.map((entry) =>
                entry.uuid === sp.uuid ? { ...entry, enabled } : entry,
            );
        } catch (error) {
            showMessage({
                level: MessageLevel.error,
                message: msg("Failed to update Service Provider."),
                description: String(error),
            });
        } finally {
            this.updatingSPUuid = undefined;
        }
    }

    private async saveEditModal(): Promise<void> {
        if (!this.parent?.pk || !this.editingSP?.uuid) {
            return;
        }

        this.editSaving = true;
        const targetUUID = this.editingSP.uuid;

        try {
            const updated = await aki(ProvidersApi).providersSamlServiceProvidersPartialUpdate({
                id: this.parent.pk,
                spId: targetUUID,
                patchedSAMLSPRequest: {
                    enabled: this.editEnabled,
                    acsUrl: this.editAcsUrl,
                    spBinding: this.editSpBinding,
                    slsUrl: this.editSlsUrl,
                    slsBinding: this.editSlsBinding,
                    nameIdPolicy: this.editNameIdPolicy,
                    authnRequestsSigned: this.editAuthnRequestsSigned,
                    wantAssertionsSigned: this.editWantAssertionsSigned,
                    verificationKp:
                        this.editVerificationKpOverride && this.editVerificationKeyMode === "kp"
                            ? this.editVerificationKp || null
                            : null,
                    signingKp:
                        this.editSigningKpOverride && this.editSigningKeyMode === "kp"
                            ? this.editSigningKp || null
                            : null,
                    encryptionKp:
                        this.editEncryptionKpOverride && this.editEncryptionKeyMode === "kp"
                            ? this.editEncryptionKp || null
                            : null,
                    verificationKpRing:
                        this.editVerificationKpOverride && this.editVerificationKeyMode === "ring"
                            ? this.editVerificationKpRing.trim() || null
                            : null,
                    signingKpRing:
                        this.editSigningKpOverride && this.editSigningKeyMode === "ring"
                            ? this.editSigningKpRing.trim() || null
                            : null,
                    encryptionKpRing:
                        this.editEncryptionKpOverride && this.editEncryptionKeyMode === "ring"
                            ? this.editEncryptionKpRing.trim() || null
                            : null,
                    verificationKpOverride: this.editVerificationKpOverride,
                    signingKpOverride: this.editSigningKpOverride,
                    encryptionKpOverride: this.editEncryptionKpOverride,
                    freezeVerificationKp: this.editFreezeVerificationKp,
                    freezeSigningKp: this.editFreezeSigningKp,
                    freezeEncryptionKp: this.editFreezeEncryptionKp,
                    localOverrideSet: this.editLocalOverrideSet,
                    propertyMappingsOverride: this.editPropertyMappingsOverride,
                    propertyMappings: this.editPropertyMappings,
                },
            });

            this.currentSPs = this.currentSPs.map((entry) =>
                entry.uuid === targetUUID ? updated : entry,
            );
            this.closeEditModal();

            showMessage({
                level: MessageLevel.success,
                message: msg("Service Provider settings updated."),
            });
        } catch (error) {
            showMessage({
                level: MessageLevel.error,
                message: msg("Failed to update Service Provider settings."),
                description: String(error),
            });
        } finally {
            this.editSaving = false;
        }
    }

    private async deleteSP(): Promise<void> {
        if (!this.parent?.pk || this.deletingSPs.length < 1) {
            return;
        }

        this.deleteLoading = true;
        const targets = this.deletingSPs.filter((sp) => Boolean(sp.uuid));
        if (targets.length < 1) {
            this.closeDeleteModal();
            return;
        }

        try {
            const parentPk = this.parent.pk;
            const api = aki(ProvidersApi);
            const outcomes = await Promise.all(
                targets.map(async (sp) => {
                    try {
                        await api.providersSamlServiceProvidersDestroy({
                            id: parentPk,
                            spId: sp.uuid!,
                        });
                        return { ok: true as const, sp };
                    } catch (error) {
                        return { ok: false as const, sp, error };
                    }
                }),
            );

            const deletedUuids = outcomes
                .filter((outcome) => outcome.ok)
                .map((outcome) => outcome.sp.uuid)
                .filter((entryUuid): entryUuid is string => Boolean(entryUuid));
            const failed = outcomes.filter((outcome) => !outcome.ok);

            if (deletedUuids.length > 0) {
                this.currentSPs = this.currentSPs.filter(
                    (entry) => !entry.uuid || !deletedUuids.includes(entry.uuid),
                );
                this.selectedCurrentSPUuids = this.selectedCurrentSPUuids.filter(
                    (entryUuid) => !deletedUuids.includes(entryUuid),
                );
            }

            this.closeDeleteModal();

            if (failed.length === 0) {
                showMessage({
                    level: MessageLevel.success,
                    message:
                        deletedUuids.length === 1
                            ? msg("Service Provider deleted.")
                            : msg("Service Providers deleted."),
                    description: String(deletedUuids.length),
                });
            } else {
                const failedLabels = failed.map((outcome) => this.getDisplayNameForSP(outcome.sp));
                showMessage({
                    level: MessageLevel.warning,
                    message: msg("Some Service Providers could not be deleted."),
                    description: failedLabels.join(", "),
                });
            }
        } catch (error) {
            showMessage({
                level: MessageLevel.error,
                message: msg("Failed to delete Service Provider."),
                description: String(error),
            });
        } finally {
            this.deleteLoading = false;
        }
    }

    private renderDiffList(fields: string[] | undefined): TemplateResult {
        if (!fields || fields.length < 1) {
            return html`-`;
        }
        return html`<ul class="pf-c-list">
            ${fields.map((field) => html`<li><code>${field}</code></li>`)}
        </ul>`;
    }

    private renderDisplayCell(displayName: string, descriptor: string): TemplateResult {
        return html`
            <strong>${displayName}</strong>
            ${descriptor
                ? html`
                      <div class="pf-u-color-200" style="font-size: 12px; line-height: 1.3;">
                          ${msg("Entity ID")}: ${descriptor}
                      </div>
                  `
                : nothing}
        `;
    }

    private renderKeyRingPresence(sp: SAMLSP): TemplateResult {
        const tags: TemplateResult[] = [];
        if (sp.verificationKpRing) {
            tags.push(
                html`<span class="pf-c-label pf-m-blue"
                    ><span class="pf-c-label__content">${msg("Verification")}</span></span
                >`,
            );
        }
        if (sp.signingKpRing) {
            tags.push(
                html`<span class="pf-c-label pf-m-blue"
                    ><span class="pf-c-label__content">${msg("Signing")}</span></span
                >`,
            );
        }
        if (sp.encryptionKpRing) {
            tags.push(
                html`<span class="pf-c-label pf-m-blue"
                    ><span class="pf-c-label__content">${msg("Encryption")}</span></span
                >`,
            );
        }
        if (tags.length < 1) {
            return html`-`;
        }
        return html`<div class="pf-u-display-flex pf-u-flex-wrap pf-u-gap-xs">${tags}</div>`;
    }

    private renderPreviewTable(): TemplateResult {
        if (this.previewRows.length < 1) {
            return html`
                <p class="pf-u-color-200">
                    ${msg("No preview data yet. Select a file and run Preview.")}
                </p>
            `;
        }

        const rows = this.getFilteredPreviewRows();

        if (rows.length < 1) {
            return html`<p class="pf-u-color-200">
                ${msg("No entities match the current search.")}
            </p>`;
        }

        return html`
            <table class="pf-c-table pf-m-grid-md" role="grid" aria-label="Preview table">
                <thead>
                    <tr>
                        <th>
                            <input
                                type="checkbox"
                                .checked=${this.areAllPreviewRowsSelected()}
                                @change=${(event: Event) => {
                                    const target = event.currentTarget as HTMLInputElement;
                                    this.setAllPreviewRows(target.checked);
                                }}
                            />
                        </th>
                        <th>${msg("Display")}</th>
                        <th>${msg("State")}</th>
                        <th>${msg("Runtime diff")}</th>
                        <th>${msg("Certificate diff")}</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows.map((row) => {
                        const idx = this.previewRows.indexOf(row);
                        const variant = this.compareStateVariant(row.item);
                        const hasRuntimeDeviated = row.item.compare.runtimeDeviated;
                        const hasCertDeviated = row.item.compare.certDeviated;
                        const displayName = this.getDisplayNameForItem(row.item);
                        const descriptor = this.getDescriptorForItem(row.item);
                        return html`
                            <tr>
                                <td>
                                    <input
                                        type="checkbox"
                                        .checked=${row.selected}
                                        @change=${(event: Event) => {
                                            const target = event.currentTarget as HTMLInputElement;
                                            this.previewRows = this.previewRows.map(
                                                (entry, entryIdx) => {
                                                    if (entryIdx !== idx) {
                                                        return entry;
                                                    }
                                                    return { ...entry, selected: target.checked };
                                                },
                                            );
                                        }}
                                    />
                                </td>
                                <td>${this.renderDisplayCell(displayName, descriptor)}</td>
                                <td>
                                    <span
                                        class="pf-c-label ${variant === "green"
                                            ? "pf-m-green"
                                            : variant === "blue"
                                              ? "pf-m-blue"
                                              : ""}"
                                    >
                                        <span class="pf-c-label__content"
                                            >${this.compareStateLabel(row.item)}</span
                                        >
                                    </span>
                                    ${hasRuntimeDeviated
                                        ? html`<span class="pf-c-label pf-m-orange pf-u-ml-sm"
                                              ><span class="pf-c-label__content"
                                                  >${msg("Runtime deviated")}</span
                                              ></span
                                          >`
                                        : nothing}
                                    ${hasCertDeviated
                                        ? html`<span class="pf-c-label pf-m-orange pf-u-ml-sm"
                                              ><span class="pf-c-label__content"
                                                  >${msg("Certificate deviated")}</span
                                              ></span
                                          >`
                                        : nothing}
                                </td>
                                <td>${this.renderDiffList(row.item.compare.runtimeDiffFields)}</td>
                                <td>${this.renderDiffList(row.item.compare.certDiffFields)}</td>
                            </tr>
                        `;
                    })}
                </tbody>
            </table>
        `;
    }

    private renderApplyResult(): TemplateResult {
        if (!this.applyResult) {
            return html``;
        }

        const results = Array.isArray(this.applyResult.results) ? this.applyResult.results : [];

        return html`
            <div class="pf-u-mt-md">
                <h4 class="pf-c-title pf-m-md">${msg("Last apply result")}</h4>
                <p>
                    ${msg("Created")}: <strong>${this.applyResult.summary.created}</strong>,
                    ${msg("Updated")}: <strong>${this.applyResult.summary.updated}</strong>,
                    ${msg("Skipped")}: <strong>${this.applyResult.summary.skipped}</strong>
                </p>
                <ul class="pf-c-list">
                    ${results.map((result) => {
                        return html`<li>
                            <strong>${result.entityId}</strong>: ${result.status}
                            ${result.reason ? html`(${result.reason})` : nothing}
                        </li>`;
                    })}
                </ul>
            </div>
        `;
    }

    private renderCurrentTable(): TemplateResult {
        if (this.loadingCurrent) {
            return html`<p>${msg("Loading Service Providers...")}</p>`;
        }

        if (!Array.isArray(this.currentSPs) || this.currentSPs.length < 1) {
            return html`<p>${msg("No Service Providers configured yet.")}</p>`;
        }

        const rows = this.getFilteredCurrentSPs();

        if (rows.length < 1) {
            return html`<p class="pf-u-color-200">
                ${msg("No entities match the current search.")}
            </p>`;
        }

        return html`
            <table class="pf-c-table pf-m-grid-md" role="grid" aria-label="Service Providers table">
                <thead>
                    <tr>
                        <th>
                            <input
                                type="checkbox"
                                .checked=${this.areAllCurrentRowsSelected(rows)}
                                @change=${(event: Event) => {
                                    const target = event.currentTarget as HTMLInputElement;
                                    this.setAllCurrentRowsSelected(rows, target.checked);
                                }}
                            />
                        </th>
                        <th>${msg("Enabled")}</th>
                        <th>${msg("Display")}</th>
                        <th>${msg("Keys")}</th>
                        <th>${msg("Actions")}</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows.map((sp) => {
                        const disabled = this.updatingSPUuid === sp.uuid;
                        const isEnabled = Boolean(sp.enabled);
                        const loadingSettings = this.openingEditUuid === sp.uuid;
                        const displayName = this.getDisplayNameForSP(sp);
                        const descriptor = this.getDescriptorForSP(sp);

                        return html`
                            <tr>
                                <td>
                                    <input
                                        type="checkbox"
                                        .checked=${this.isCurrentRowSelected(sp)}
                                        @change=${(event: Event) => {
                                            const target = event.currentTarget as HTMLInputElement;
                                            this.setCurrentRowSelected(sp, target.checked);
                                        }}
                                    />
                                </td>
                                <td>
                                    <label class="pf-c-switch" for="sp-enabled-${sp.uuid}">
                                        <input
                                            class="pf-c-switch__input"
                                            type="checkbox"
                                            id="sp-enabled-${sp.uuid}"
                                            ?checked=${isEnabled}
                                            ?disabled=${disabled}
                                            @change=${(event: Event) => {
                                                const target =
                                                    event.currentTarget as HTMLInputElement;
                                                this.updateSPEnabled(sp, target.checked);
                                            }}
                                        />
                                        <span class="pf-c-switch__toggle"></span>
                                        <span class="pf-c-switch__label"
                                            >${isEnabled ? msg("Enabled") : msg("Disabled")}</span
                                        >
                                    </label>
                                </td>
                                <td>${this.renderDisplayCell(displayName, descriptor)}</td>
                                <td>${this.renderKeyRingPresence(sp)}</td>
                                <td>
                                    <div class="pf-u-display-flex pf-u-gap-sm">
                                        <button
                                            aria-label=${msg("Edit Service Provider settings")}
                                            class="pf-c-button pf-m-plain"
                                            type="button"
                                            ?disabled=${loadingSettings}
                                            @click=${() => this.openEditModal(sp)}
                                        >
                                            <pf-tooltip position="top" content=${msg("Edit")}>
                                                <i aria-hidden="true" class="fas fa-edit"></i>
                                            </pf-tooltip>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    })}
                </tbody>
            </table>
        `;
    }

    private renderModal(
        title: string,
        body: TemplateResult,
        footer: TemplateResult,
        close: () => void,
        sizeClass = "pf-m-xl",
    ): TemplateResult {
        return html`<div class="pf-c-backdrop" role="presentation">
            <div class="pf-l-bullseye" role="presentation">
                <div
                    class="pf-c-modal-box ${sizeClass}"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="modal-title"
                >
                    <button
                        @click=${close}
                        class="pf-c-button pf-m-plain"
                        type="button"
                        aria-label=${msg("Close dialog")}
                    >
                        <i class="fas fa-times" aria-hidden="true"></i>
                    </button>
                    <section class="pf-c-modal-box__header pf-c-page__main-section pf-m-light">
                        <h1 id="modal-title" class="pf-c-title pf-m-2xl">${title}</h1>
                    </section>
                    <section class="pf-c-modal-box__body pf-m-light">${body}</section>
                    <fieldset class="pf-c-modal-box__footer">
                        <legend class="sr-only">${msg("Form actions")}</legend>
                        ${footer}
                    </fieldset>
                </div>
            </div>
        </div>`;
    }

    private setEditCertificate(
        field: "verification" | "signing" | "encryption",
        event: Event,
    ): void {
        const target = event.currentTarget as { value?: string | null };
        const value = target.value ?? undefined;
        if (field === "verification") {
            this.editVerificationKp = value;
            return;
        }
        if (field === "signing") {
            this.editSigningKp = value;
            return;
        }
        this.editEncryptionKp = value;
    }

    private renderEditRingControl(
        fieldName: "editVerificationKpRing" | "editSigningKpRing" | "editEncryptionKpRing",
        ringUuid: string,
        label: string,
        requireKey = false,
    ): TemplateResult {
        const hasRing = !!ringUuid;
        return html`<ak-form-element-horizontal label=${label} name=${fieldName}>
            <div class="pf-c-input-group" style="width: 100%;">
                ${hasRing
                    ? html`<ak-forms-modal size=${PFSize.XLarge}>
                          <span slot="header">${msg("Manage key ring")}</span>
                          <span slot="submit">${msg("Save")}</span>
                          <ak-crypto-keyring-manager-form
                              slot="form"
                              ring-uuid=${ringUuid}
                              ?require-key=${requireKey}
                          ></ak-crypto-keyring-manager-form>
                          <button slot="trigger" class="pf-c-button pf-m-secondary" type="button">
                              ${msg("Manage")}
                          </button>
                      </ak-forms-modal>`
                    : html`<button class="pf-c-button pf-m-secondary" type="button" disabled>
                          ${msg("Not created")}
                      </button>`}
            </div>
            <p class="pf-c-form__helper-text">
                ${hasRing
                    ? msg("This ring is bound to this service provider.")
                    : msg("No ring is attached yet. Apply metadata to create.")}
            </p>
        </ak-form-element-horizontal>`;
    }

    private onPropertyMappingsChange(event: CustomEvent<{ value?: DualSelectPair[] }>): void {
        const selected = event.detail?.value || [];
        this.editPropertyMappings = selected
            .map((entry) => String(entry[0] || ""))
            .filter((pk) => pk.length > 0);
    }

    private renderImportModal(): TemplateResult {
        if (!this.importModalOpen) {
            return html``;
        }

        const body = html`
            <div class="pf-c-form">
                <ak-file-search-input
                    name="fileRef"
                    label=${msg("Metadata file")}
                    .usage=${UsageEnum.SamlMetadata}
                    .value=${this.fileRef}
                    required
                    @ak-change=${this.onFileRefChange}
                ></ak-file-search-input>

                <ak-form-element-horizontal
                    name="signingCertificate"
                    label=${msg("Trust anchor certificate")}
                >
                    <ak-crypto-certificate-search
                        nokey
                        @input=${this.onSigningCertificateInput}
                    ></ak-crypto-certificate-search>
                </ak-form-element-horizontal>

                <ak-form-element-horizontal name="applyPolicy" label=${msg("Apply policy")}>
                    <select
                        class="pf-c-form-control"
                        .value=${this.applyPolicy}
                        @change=${(event: Event) => {
                            const target = event.currentTarget as HTMLSelectElement;
                            this.applyPolicy = target.value as ApplyPolicyEnum;
                        }}
                    >
                        <option value=${ApplyPolicyEnum.IfNotDeviated}>
                            ${msg("Apply if not deviated")}
                        </option>
                        <option value=${ApplyPolicyEnum.Force}>${msg("Force apply")}</option>
                    </select>
                </ak-form-element-horizontal>

                <ak-switch-input
                    label=${msg("Create missing key rings")}
                    .checked=${this.createMissingRings}
                    @change=${(event: Event) => {
                        const target = event.target as HTMLInputElement;
                        this.createMissingRings = target.checked;
                    }}
                ></ak-switch-input>

                <div class="pf-u-mt-md pf-u-display-flex pf-u-gap-md">
                    <ak-spinner-button
                        class="pf-m-secondary"
                        .disabled=${this.previewLoading || !this.fileRef}
                        .callAction=${async () => this.previewFromFile()}
                    >
                        ${msg("Preview")}
                    </ak-spinner-button>
                    <ak-spinner-button
                        class="pf-m-primary"
                        .disabled=${this.applyLoading ||
                        this.previewRows.length < 1 ||
                        !this.hasSelectedPreviewRows()}
                        .callAction=${async () => this.applySelected()}
                    >
                        ${msg("Apply selected")}
                    </ak-spinner-button>
                </div>
            </div>

            <div class="pf-u-mt-lg">
                <div class="pf-u-mb-sm">
                    <input
                        class="pf-c-form-control"
                        type="search"
                        placeholder=${msg("Search by DisplayName or Entity ID")}
                        .value=${this.previewSearch}
                        @input=${(event: Event) => {
                            const target = event.currentTarget as HTMLInputElement;
                            this.previewSearch = target.value;
                        }}
                    />
                </div>
                ${this.renderPreviewTable()} ${this.renderApplyResult()}
            </div>
        `;

        const footer = html`<button class="pf-c-button pf-m-plain" @click=${this.closeImportModal}>
            ${msg("Close")}
        </button>`;

        return this.renderModal(
            msg("Import and preview metadata"),
            body,
            footer,
            () => this.closeImportModal(),
            "pf-m-xl",
        );
    }

    private renderEditModal(): TemplateResult {
        if (!this.editingSP) {
            return html``;
        }

        const displayName = this.getDisplayNameForSP(this.editingSP);
        const entityId = this.editingSP.entityId;

        const body = html`<form
            class="pf-c-form pf-m-horizontal"
            @submit=${(event: SubmitEvent) => {
                event.preventDefault();
                this.saveEditModal();
            }}
        >
            <div class="pf-u-mb-md">
                <h4 class="pf-c-title pf-m-md">${msg("Entity settings")}</h4>
            </div>
            <div class="pf-c-form__group">
                <label class="pf-c-form__label" for="edit-sp-name">
                    <span class="pf-c-form__label-text">${msg("Display name")}</span>
                </label>
                <input
                    id="edit-sp-name"
                    class="pf-c-form-control"
                    type="text"
                    .value=${displayName}
                    readonly
                />
            </div>
            <div class="pf-c-form__group">
                <label class="pf-c-form__label" for="edit-sp-entity-id">
                    <span class="pf-c-form__label-text">${msg("Entity ID")}</span>
                </label>
                <input
                    id="edit-sp-entity-id"
                    class="pf-c-form-control"
                    type="text"
                    .value=${entityId}
                    readonly
                />
            </div>
            <ak-switch-input
                label=${msg("Enabled")}
                .checked=${this.editEnabled}
                @change=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.editEnabled = target.checked;
                }}
            ></ak-switch-input>

            <div
                role="separator"
                style="border-top: 1px solid var(--pf-global--BorderColor--100); margin: 1rem 0;"
            ></div>
            <div class="pf-u-mb-md">
                <h4 class="pf-c-title pf-m-md">${msg("Protocol settings")}</h4>
            </div>
            <div class="pf-c-form__group">
                <label class="pf-c-form__label" for="edit-sp-acs-url">
                    <span class="pf-c-form__label-text">${msg("ACS URL")}</span>
                </label>
                <input
                    id="edit-sp-acs-url"
                    class="pf-c-form-control"
                    type="url"
                    required
                    .value=${this.editAcsUrl}
                    @input=${(event: Event) => {
                        const target = event.currentTarget as HTMLInputElement;
                        this.editAcsUrl = target.value;
                    }}
                />
            </div>
            <div class="pf-c-form__group">
                <label class="pf-c-form__label" for="edit-sp-binding">
                    <span class="pf-c-form__label-text">${msg("ACS binding")}</span>
                </label>
                <select
                    id="edit-sp-binding"
                    class="pf-c-form-control"
                    @change=${(event: Event) => {
                        const target = event.currentTarget as HTMLSelectElement;
                        this.editSpBinding = this.normalizeBindingToken(
                            target.value,
                            SAMLBindingsEnum.Post,
                        );
                    }}
                >
                    <option
                        value=${SAMLBindingsEnum.Redirect}
                        ?selected=${this.editSpBinding === SAMLBindingsEnum.Redirect}
                    >
                        ${msg("Redirect")}
                    </option>
                    <option
                        value=${SAMLBindingsEnum.Post}
                        ?selected=${this.editSpBinding === SAMLBindingsEnum.Post}
                    >
                        ${msg("Post")}
                    </option>
                </select>
            </div>
            <ak-switch-input
                label=${msg("Authn request signed")}
                .checked=${this.editAuthnRequestsSigned}
                help=${msg("Mark this service provider as sending signed AuthnRequests.")}
                @change=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.editAuthnRequestsSigned = target.checked;
                }}
            ></ak-switch-input>
            <ak-switch-input
                label=${msg("Want assertions signed")}
                .checked=${this.editWantAssertionsSigned}
                help=${msg("Require signed assertions for this service provider.")}
                @change=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.editWantAssertionsSigned = target.checked;
                }}
            ></ak-switch-input>
            <div class="pf-c-form__group">
                <label class="pf-c-form__label" for="edit-sp-sls-url">
                    <span class="pf-c-form__label-text">${msg("SLS URL")}</span>
                </label>
                <input
                    id="edit-sp-sls-url"
                    class="pf-c-form-control"
                    type="url"
                    .value=${this.editSlsUrl}
                    @input=${(event: Event) => {
                        const target = event.currentTarget as HTMLInputElement;
                        this.editSlsUrl = target.value;
                    }}
                />
            </div>
            <div class="pf-c-form__group">
                <label class="pf-c-form__label" for="edit-sp-sls-binding">
                    <span class="pf-c-form__label-text">${msg("SLS binding")}</span>
                </label>
                <select
                    id="edit-sp-sls-binding"
                    class="pf-c-form-control"
                    @change=${(event: Event) => {
                        const target = event.currentTarget as HTMLSelectElement;
                        this.editSlsBinding = this.normalizeBindingToken(
                            target.value,
                            SAMLBindingsEnum.Redirect,
                        );
                    }}
                >
                    <option
                        value=${SAMLBindingsEnum.Redirect}
                        ?selected=${this.editSlsBinding === SAMLBindingsEnum.Redirect}
                    >
                        ${msg("Redirect")}
                    </option>
                    <option
                        value=${SAMLBindingsEnum.Post}
                        ?selected=${this.editSlsBinding === SAMLBindingsEnum.Post}
                    >
                        ${msg("Post")}
                    </option>
                </select>
            </div>
            <div class="pf-c-form__group">
                <label class="pf-c-form__label" for="edit-sp-nameid-policy">
                    <span class="pf-c-form__label-text">${msg("NameID policy")}</span>
                </label>
                <select
                    id="edit-sp-nameid-policy"
                    class="pf-c-form-control"
                    @change=${(event: Event) => {
                        const target = event.currentTarget as HTMLSelectElement;
                        this.editNameIdPolicy = this.normalizeNameIdPolicy(target.value);
                    }}
                >
                    <option
                        value=${SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml20NameidFormatPersistent}
                        ?selected=${this.editNameIdPolicy ===
                        SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml20NameidFormatPersistent}
                    >
                        ${msg("Persistent")}
                    </option>
                    <option
                        value=${SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml11NameidFormatEmailAddress}
                        ?selected=${this.editNameIdPolicy ===
                        SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml11NameidFormatEmailAddress}
                    >
                        ${msg("Email address")}
                    </option>
                    <option
                        value=${SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml20NameidFormatWindowsDomainQualifiedName}
                        ?selected=${this.editNameIdPolicy ===
                        SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml20NameidFormatWindowsDomainQualifiedName}
                    >
                        ${msg("Windows")}
                    </option>
                    <option
                        value=${SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml11NameidFormatX509SubjectName}
                        ?selected=${this.editNameIdPolicy ===
                        SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml11NameidFormatX509SubjectName}
                    >
                        ${msg("X509 Subject")}
                    </option>
                    <option
                        value=${SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml20NameidFormatTransient}
                        ?selected=${this.editNameIdPolicy ===
                        SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml20NameidFormatTransient}
                    >
                        ${msg("Transient")}
                    </option>
                    <option
                        value=${SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml11NameidFormatUnspecified}
                        ?selected=${this.editNameIdPolicy ===
                        SAMLNameIDPolicyEnum.UrnOasisNamesTcSaml11NameidFormatUnspecified}
                    >
                        ${msg("Unspecified")}
                    </option>
                </select>
            </div>
            <div
                role="separator"
                style="border-top: 1px solid var(--pf-global--BorderColor--100); margin: 1rem 0;"
            ></div>
            <div class="pf-u-mb-md">
                <h4 class="pf-c-title pf-m-md">${msg("Key settings")}</h4>
            </div>
            <div class="pf-u-mb-sm">
                <strong>${msg("Verification keys")}</strong>
            </div>
            <ak-switch-input
                label=${msg("Verification key override")}
                .checked=${this.editVerificationKpOverride}
                help=${msg("Use local key; otherwise inherit from owner.")}
                @change=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.editVerificationKpOverride = target.checked;
                }}
            ></ak-switch-input>
            ${this.editVerificationKpOverride
                ? html`<ak-radio-input
                          label=${msg("Verification key source")}
                          name="editVerificationKeyMode"
                          .options=${keyModeOptions}
                          .value=${this.editVerificationKeyMode}
                          help=${msg(
                              "Choose a single certificate or a key ring for request/response verification.",
                          )}
                          @change=${(event: Event) => {
                              const target = event.target as HTMLInputElement;
                              this.editVerificationKeyMode = target.value as KeyMode;
                          }}
                      >
                      </ak-radio-input>
                      ${this.editVerificationKeyMode === "kp"
                          ? html`<ak-form-element-horizontal
                                label=${msg("Verification certificate")}
                                name="editVerificationKp"
                            >
                                <ak-crypto-certificate-search
                                    nokey
                                    .certificate=${this.editVerificationKp}
                                    @input=${(event: Event) =>
                                        this.setEditCertificate("verification", event)}
                                ></ak-crypto-certificate-search>
                            </ak-form-element-horizontal>`
                          : this.renderEditRingControl(
                                "editVerificationKpRing",
                                this.editVerificationKpRing,
                                msg("Verification key ring"),
                            )}
                      <ak-switch-input
                          label=${msg("Freeze verification key")}
                          .checked=${this.editFreezeVerificationKp}
                          help=${msg(
                              "Prevent metadata import from updating verification key settings.",
                          )}
                          @change=${(event: Event) => {
                              const target = event.target as HTMLInputElement;
                              this.editFreezeVerificationKp = target.checked;
                          }}
                      ></ak-switch-input>`
                : nothing}

            <div
                role="separator"
                style="border-top: 1px solid var(--pf-global--BorderColor--100); margin: 1rem 0;"
            ></div>
            <div class="pf-u-mb-sm">
                <strong>${msg("Signing keys")}</strong>
            </div>
            <ak-switch-input
                label=${msg("Signing key override")}
                .checked=${this.editSigningKpOverride}
                help=${msg("Use local key; otherwise inherit from owner.")}
                @change=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.editSigningKpOverride = target.checked;
                }}
            ></ak-switch-input>
            ${this.editSigningKpOverride
                ? html`<ak-radio-input
                          label=${msg("Signing key source")}
                          name="editSigningKeyMode"
                          .options=${keyModeOptions}
                          .value=${this.editSigningKeyMode}
                          help=${msg("Choose a single keypair or a key ring for signing.")}
                          @change=${(event: Event) => {
                              const target = event.target as HTMLInputElement;
                              this.editSigningKeyMode = target.value as KeyMode;
                          }}
                      >
                      </ak-radio-input>
                      ${this.editSigningKeyMode === "kp"
                          ? html`<ak-form-element-horizontal
                                label=${msg("Signing keypair")}
                                name="editSigningKp"
                            >
                                <ak-crypto-certificate-search
                                    .certificate=${this.editSigningKp}
                                    @input=${(event: Event) =>
                                        this.setEditCertificate("signing", event)}
                                ></ak-crypto-certificate-search>
                            </ak-form-element-horizontal>`
                          : this.renderEditRingControl(
                                "editSigningKpRing",
                                this.editSigningKpRing,
                                msg("Signing key ring"),
                                true,
                            )}
                      <ak-switch-input
                          label=${msg("Freeze signing key")}
                          .checked=${this.editFreezeSigningKp}
                          help=${msg("Prevent metadata import from updating signing key settings.")}
                          @change=${(event: Event) => {
                              const target = event.target as HTMLInputElement;
                              this.editFreezeSigningKp = target.checked;
                          }}
                      ></ak-switch-input>`
                : nothing}

            <div
                role="separator"
                style="border-top: 1px solid var(--pf-global--BorderColor--100); margin: 1rem 0;"
            ></div>
            <div class="pf-u-mb-sm">
                <strong>${msg("Encryption keys")}</strong>
            </div>
            <ak-switch-input
                label=${msg("Encryption key override")}
                .checked=${this.editEncryptionKpOverride}
                help=${msg("Use local key; otherwise inherit from owner.")}
                @change=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.editEncryptionKpOverride = target.checked;
                }}
            ></ak-switch-input>
            ${this.editEncryptionKpOverride
                ? html`<ak-radio-input
                          label=${msg("Encryption key source")}
                          name="editEncryptionKeyMode"
                          .options=${keyModeOptions}
                          .value=${this.editEncryptionKeyMode}
                          help=${msg("Choose a single certificate or a key ring for encryption.")}
                          @change=${(event: Event) => {
                              const target = event.target as HTMLInputElement;
                              this.editEncryptionKeyMode = target.value as KeyMode;
                          }}
                      >
                      </ak-radio-input>
                      ${this.editEncryptionKeyMode === "kp"
                          ? html`<ak-form-element-horizontal
                                label=${msg("Encryption certificate")}
                                name="editEncryptionKp"
                            >
                                <ak-crypto-certificate-search
                                    nokey
                                    .certificate=${this.editEncryptionKp}
                                    @input=${(event: Event) =>
                                        this.setEditCertificate("encryption", event)}
                                ></ak-crypto-certificate-search>
                            </ak-form-element-horizontal>`
                          : this.renderEditRingControl(
                                "editEncryptionKpRing",
                                this.editEncryptionKpRing,
                                msg("Encryption key ring"),
                            )}
                      <ak-switch-input
                          label=${msg("Freeze encryption key")}
                          .checked=${this.editFreezeEncryptionKp}
                          help=${msg(
                              "Prevent metadata import from updating encryption key settings.",
                          )}
                          @change=${(event: Event) => {
                              const target = event.target as HTMLInputElement;
                              this.editFreezeEncryptionKp = target.checked;
                          }}
                      ></ak-switch-input>`
                : nothing}

            <div
                role="separator"
                style="border-top: 1px solid var(--pf-global--BorderColor--100); margin: 1rem 0;"
            ></div>
            <div class="pf-u-mb-md">
                <h4 class="pf-c-title pf-m-md">${msg("Metadata controls")}</h4>
            </div>
            <ak-switch-input
                label=${msg("Local override set")}
                .checked=${this.editLocalOverrideSet}
                help=${msg(
                    "Mark this entity as locally managed. 'Apply if not deviated' will skip runtime updates.",
                )}
                @change=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.editLocalOverrideSet = target.checked;
                }}
            ></ak-switch-input>
            <ak-switch-input
                label=${msg("Property mappings override")}
                .checked=${this.editPropertyMappingsOverride}
                help=${msg(
                    "Use local property mappings; otherwise inherit mappings from the parent provider.",
                )}
                @change=${(event: Event) => {
                    const target = event.target as HTMLInputElement;
                    this.editPropertyMappingsOverride = target.checked;
                }}
            ></ak-switch-input>
            ${this.editPropertyMappingsOverride
                ? html`<ak-form-element-horizontal
                      label=${msg("Property mappings")}
                      name="editPropertyMappings"
                  >
                      <ak-dual-select-dynamic-selected
                          .provider=${propertyMappingsProvider}
                          .selector=${propertyMappingsSelector(this.editPropertyMappings)}
                          available-label=${msg("Available User Property Mappings")}
                          selected-label=${msg("Selected User Property Mappings")}
                          @ak-dual-select-change=${(
                              event: CustomEvent<{ value?: DualSelectPair[] }>,
                          ) => this.onPropertyMappingsChange(event)}
                      ></ak-dual-select-dynamic-selected>
                  </ak-form-element-horizontal>`
                : nothing}
        </form>`;

        const footer = html`
            <button class="pf-c-button pf-m-plain" @click=${this.closeEditModal}>
                ${msg("Cancel")}
            </button>
            <ak-spinner-button
                class="pf-m-primary"
                .disabled=${this.editSaving}
                .callAction=${async () => this.saveEditModal()}
            >
                ${msg("Save changes")}
            </ak-spinner-button>
        `;

        return this.renderModal(
            msg("Update Service Provider settings"),
            body,
            footer,
            () => this.closeEditModal(),
            "pf-m-lg",
        );
    }

    private renderDeleteModal(): TemplateResult {
        if (this.deletingSPs.length < 1) {
            return html``;
        }

        const labels = this.deletingSPs.map((sp) => this.getDisplayNameForSP(sp));
        const previewLabels = labels.slice(0, 5);
        const extraCount = labels.length - previewLabels.length;

        const body = html`<p>
                ${labels.length === 1
                    ? msg("Are you sure you want to delete this Service Provider?")
                    : msg("Are you sure you want to delete these Service Providers?")}
            </p>
            <ul class="pf-c-list">
                ${previewLabels.map((label) => html`<li><strong>${label}</strong></li>`)}
            </ul>
            ${extraCount > 0 ? html`<p>${msg("And more")}: ${extraCount}</p>` : nothing}`;

        const footer = html`
            <button class="pf-c-button pf-m-plain" @click=${this.closeDeleteModal}>
                ${msg("Cancel")}
            </button>
            <ak-spinner-button
                class="pf-m-danger"
                .disabled=${this.deleteLoading}
                .callAction=${async () => this.deleteSP()}
            >
                ${msg("Delete")}
            </ak-spinner-button>
        `;

        return this.renderModal(
            msg("Delete Service Provider"),
            body,
            footer,
            () => this.closeDeleteModal(),
            "pf-m-md",
        );
    }

    render(): TemplateResult {
        return html`
            <div class="pf-u-mb-lg">
                <button
                    class="pf-c-button pf-m-secondary"
                    type="button"
                    @click=${() => this.openImportModal()}
                >
                    ${msg("Import from metadata")}
                </button>
            </div>

            <div>
                <h3 class="pf-c-title pf-m-lg pf-u-mb-md">${msg("Current Service Providers")}</h3>
                <div class="pf-u-mb-md pf-u-display-flex pf-u-gap-sm">
                    <button
                        class="pf-c-button pf-m-danger"
                        type="button"
                        ?disabled=${this.selectedCurrentSPUuids.length < 1}
                        @click=${() => this.openBulkDeleteModal()}
                    >
                        ${msg("Delete selected")}
                    </button>
                </div>
                <div class="pf-u-mb-sm">
                    <input
                        class="pf-c-form-control"
                        type="search"
                        placeholder=${msg("Search by DisplayName or Entity ID")}
                        .value=${this.currentSearch}
                        @input=${(event: Event) => {
                            const target = event.currentTarget as HTMLInputElement;
                            this.currentSearch = target.value;
                        }}
                    />
                </div>
                ${this.renderCurrentTable()}
            </div>

            ${this.renderImportModal()} ${this.renderEditModal()} ${this.renderDeleteModal()}
        `;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-provider-saml-sp-tab": SAMLProviderSPTab;
    }
}

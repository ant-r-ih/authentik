// authentik/web/src/admin/providers/saml/SAMLSPSnapshotImport.ts
//
// Common SnapshotImport for SAML SP/IdP (kind switch).
//
// Policy (updated):
// - "Local settings" opens an inline editor panel (no overlay modal)
// - Panel Save => immediate PATCH to DB (inside panel component)
// - Panel Cancel/Close => no DB change
// - SnapshotImport no longer stages DB-local settings for Apply
// - SnapshotImport still manages preview/import/delete staging
//
// Additions in this version:
// - Signature verification controls:
//   - Verify signature (switch)
//   - Signing certificate (optional) via ak-crypto-certificate-search
// - Preview/entity calls include verify_signature + signing_certificate (pk) when enabled
// - Signature result banner is shown from backend meta.signature (if present)
// - Row merge policy (A):
//   - Preview + DB are merged by normalized entity_id
//   - A merged row is a DB row (uuid is preserved) with current-state coming from preview
//   - Stage import can apply to BOTH preview-only rows and merged DB rows
// - Row layout: checkbox alignment hardened (line-height:0 + align-items:center) to avoid Safari drift

import { customElement, property, state } from "lit/decorators.js";
import { html, nothing, type TemplateResult } from "lit";
import { msg } from "@lit/localize";

import { createRef, ref } from "lit/directives/ref.js";

import "#elements/buttons/SpinnerButton/index";
import "#components/ak-file-search-input";
import "#admin/providers/saml/SAMLSPDbLocalSettingsModal";
import "#admin/sources/saml/SAMLIDPDbLocalSettingsModal";

import "#components/ak-switch-input";
import "#admin/common/ak-crypto-certificate-search";

import { Form } from "#elements/forms/Form";
import { showMessage } from "#elements/messages/MessageContainer";
import { MessageLevel } from "#common/messages";
import { DEFAULT_CONFIG } from "#common/api/config";

import { AdminFileListUsageEnum, ProvidersApi, SourcesApi } from "@goauthentik/api";

async function readErrorBody(res: Response): Promise<string> {
    const ct = res.headers.get("content-type") ?? "";
    try {
        if (ct.includes("application/json")) {
            const j = await res.json();
            return JSON.stringify(j);
        }
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

type CatalogState = "unknown" | "new" | "unchanged" | "updated";
type RowKind = "db" | "preview";
type PlannedAction = "none" | "import" | "delete";
type Kind = "sp" | "idp";

type SignatureStatus = "ok" | "stale" | "invalid" | "unsigned" | "skipped" | "error" | string;

type SignatureMeta = {
    status: SignatureStatus;
    message?: string;
    metadata_id?: string | null;
    metadata_name?: string | null;
    root_tag?: string | null;
    valid_until?: string | null;
    is_stale?: boolean;
    signature_nodes?: number;
};

type SAMLMetadataCatalogItem = {
    entity_id: string;
    kind?: string[];
    display_name?: string | null;
    container_name_chain?: string[];
    states?: {
        metadata?: CatalogState;
        metadata_hash?: string;
        runtime?: string;
    };
};

type CatalogPreviewResponse = {
    meta?: {
        signature?: SignatureMeta;
    };
    items: SAMLMetadataCatalogItem[];
};

type CatalogEntityResponse = {
    entity_id: string;
    xml: string;
    container_name_chain?: string[];
};

type CatalogOptions = {
    verifySignature?: boolean;
    signingCertificate?: string | null; // CertificateKeyPair.pk (stringified)
};

type SAMLSPImportLocalSettings = {
    propertyMappingsOverride?: boolean;
    propertyMappings?: string[]; // mapping pk[]
};

type RowLocalSettingsSummary =
    | { mode: "inherit" }
    | { mode: "none" }
    | { mode: "set"; count: number };

// unified managed-list row (DB)
type ManagedItem = {
    uuid: string;
    entity_id: string;
    name?: string | null;
    property_mappings_override?: boolean;
    property_mappings?: string[];

    // SP: new boolean overrides (preferred)
    verification_kp_override?: boolean | null;
    encryption_kp_override?: boolean | null;
    signing_kp_override?: boolean | null;

    // legacy IdP style / or older SP builds (kept for compatibility)
    verification_kp_mode?: string | null;
    encryption_kp_mode?: string | null;
    signing_kp_mode?: string | null;

    freeze_verification_kp?: boolean | null;
    freeze_encryption_kp?: boolean | null;
    freeze_signing_kp?: boolean | null;
};

type Row = {
    kind: RowKind;
    key: string;

    // DB identity
    uuid?: string;

    // entity identity (always present)
    entity_id?: string;
    entityIdText: string;

    // label
    label: string;

    // current state shown in badge
    current: CatalogState | "db";

    // if this DB row was merged with preview, remember preview entity id (used for re-import)
    previewEntityId?: string;

    // property mappings (SP only for now)
    propertyMappingsOverride?: boolean;
    propertyMappings?: string[];

    // For local settings panels:
    // - SP: we use boolean override flags (inherit vs force-disable UI is inside the panel)
    verificationKpOverride?: boolean;
    encryptionKpOverride?: boolean;
    signingKpOverride?: boolean;

    // - IdP: still mode strings (inherit/none/...)
    verificationKpMode?: string | null;
    encryptionKpMode?: string | null;
    signingKpMode?: string | null;

    // Optional: freeze flags to decorate UI (not used yet)
    freezeVerificationKp?: boolean;
    freezeEncryptionKp?: boolean;
    freezeSigningKp?: boolean;
};

type SPLocalSettingsSavedDetail = {
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

type IDPLocalSettingsSavedDetail = {
    idpUuid: string;
    applied: {
        verificationKeyEnabled: boolean;
        encryptionKeyEnabled: boolean;
        signingKeyEnabled: boolean;
    };
};

function apiBasePath(): string {
    return (DEFAULT_CONFIG.basePath ?? "/api/v3").replace(/\/$/, "");
}

function normEntityId(v: string): string {
    return (v ?? "").trim().replace(/\/+$/, "");
}

async function catalogPreviewByName(
    kind: Kind,
    owner: string,
    metadataName: string,
    opts?: CatalogOptions,
): Promise<CatalogPreviewResponse> {
    const url = new URL(`${apiBasePath()}/providers/saml/catalog/preview/`, window.location.origin);

    if (kind === "sp") url.searchParams.set("provider", owner);
    if (kind === "idp") url.searchParams.set("source", owner); // TODO: implement backend
    url.searchParams.set("kind", kind);

    const csrf = getCSRFToken();
    if (!csrf) throw new Error("CSRF cookie missing.");

    const body: Record<string, unknown> = { metadata_name: metadataName };

    if (opts?.verifySignature) {
        body.verify_signature = true;
        if (opts.signingCertificate) body.signing_certificate = String(opts.signingCertificate);
    } else if (opts?.verifySignature === false) {
        // explicit off (optional)
        body.verify_signature = false;
    }

    const res = await fetch(url.toString(), {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-authentik-CSRF": csrf },
        body: JSON.stringify(body),
    });

    if (!res.ok) throw new Error(`Catalog preview failed (${res.status}): ${await readErrorBody(res)}`);

    // Backend may return either a raw list (legacy) or {meta, items} (new)
    const payload = (await res.json()) as unknown;

    if (Array.isArray(payload)) {
        return { meta: undefined, items: payload as SAMLMetadataCatalogItem[] };
    }
    return payload as CatalogPreviewResponse;
}

async function catalogGetEntityByName(
    kind: Kind,
    owner: string,
    metadataName: string,
    entityId: string,
    opts?: CatalogOptions,
): Promise<CatalogEntityResponse> {
    const url = new URL(`${apiBasePath()}/providers/saml/catalog/entity/`, window.location.origin);

    if (kind === "sp") url.searchParams.set("provider", owner);
    if (kind === "idp") url.searchParams.set("source", owner); // TODO: implement backend

    const csrf = getCSRFToken();
    if (!csrf) throw new Error("CSRF cookie missing.");

    const body: Record<string, unknown> = { metadata_name: metadataName, entity_id: entityId };

    if (opts?.verifySignature) {
        body.verify_signature = true;
        if (opts.signingCertificate) body.signing_certificate = String(opts.signingCertificate);
    } else if (opts?.verifySignature === false) {
        body.verify_signature = false;
    }

    const res = await fetch(url.toString(), {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-authentik-CSRF": csrf },
        body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`Catalog entity failed (${res.status}): ${await readErrorBody(res)}`);
    return (await res.json()) as CatalogEntityResponse;
}

async function importSingleEntity(
    kind: Kind,
    ownerPk: number,
    entityDescriptorXml: string,
    localSettings?: SAMLSPImportLocalSettings,
): Promise<void> {
    const basePath = apiBasePath();

    const url =
        kind === "sp"
            ? new URL(`${basePath}/providers/samlsp/import/`, window.location.origin)
            : new URL(`${basePath}/sources/samlidp/import/`, window.location.origin); // TODO: create backend

    const csrf = getCSRFToken();
    if (!csrf) throw new Error("CSRF cookie missing.");

    const body =
        kind === "sp"
            ? {
                  provider: ownerPk,
                  entity_xml: entityDescriptorXml,
                  ...(localSettings ?? {}),
              }
            : { source: ownerPk, entity_xml: entityDescriptorXml }; // TODO: align backend

    const res = await fetch(url.toString(), {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-authentik-CSRF": csrf },
        body: JSON.stringify(body),
    });

    if (!res.ok) throw new Error(`Import failed (${res.status}): ${await readErrorBody(res)}`);
}

async function bulkDelete(kind: Kind, ownerPk: number, uuids: string[]): Promise<void> {
    const basePath = apiBasePath();

    const url =
        kind === "sp"
            ? new URL(`${basePath}/providers/samlsp/bulk-delete/`, window.location.origin)
            : new URL(`${basePath}/sources/samlidp/bulk-delete/`, window.location.origin); // TODO

    const csrf = getCSRFToken();
    if (!csrf) throw new Error("CSRF cookie missing.");

    const body = kind === "sp" ? { provider: ownerPk, uuids } : { source: ownerPk, uuids };

    const res = await fetch(url.toString(), {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-authentik-CSRF": csrf },
        body: JSON.stringify(body),
    });

    if (!res.ok) throw new Error(`Bulk delete failed (${res.status}): ${await readErrorBody(res)}`);
}

function chunk<T>(arr: T[], size: number): T[][] {
    const out: T[][] = [];
    for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
    return out;
}

@customElement("ak-saml-snapshot-import")
export class SAMLSnapshotImportForm extends Form<Record<string, unknown>> {
    @property({ type: String })
    kind: Kind = "sp";

    @property({ type: Number })
    ownerPk!: number;

    @property({ type: String })
    ownerLabel = "SAML";

    @state()
    private metadataName: string | null = null;

    // Signature verification options
    @state()
    private verifySignature = true;

    @state()
    private signingCertificatePk: string | null = null;

    @state()
    private signatureMeta: SignatureMeta | null = null;

    @state()
    private rows: Row[] = [];

    @state()
    private selectedKeys: string[] = [];

    @state()
    private plannedByKey: Record<string, PlannedAction> = {};

    @state()
    private previewLoading = false;

    @state()
    private dbLoading = false;

    @state()
    private actionLoading = false;

    @state()
    private previewError: string | null = null;

    @state()
    private search = "";

    @state()
    private progressOpen = false;

    @state()
    private progressLabel = "";

    @state()
    private progressDone = 0;

    @state()
    private progressTotal = 0;

    @state()
    private plannedLocalSettingsByKey: Record<string, SAMLSPImportLocalSettings> = {};

    @state()
    private localSettingsOpen = false;

    @state()
    private localSettingsRowKey: string | null = null;

    private selectAllRef = createRef<HTMLInputElement>();

    private get catalogOpts(): CatalogOptions {
        return {
            verifySignature: !!this.verifySignature,
            signingCertificate: this.signingCertificatePk,
        };
    }

    private onSigningCertChanged = (ev: Event): void => {
        const t = ev.target as any;
        const ce = ev as CustomEvent<any>;
        const d = (ce as any)?.detail ?? {};

        const pk =
            d?.value?.pk ??
            d?.value ??
            d?.certificate?.pk ??
            t?.certificate?.pk ??
            t?.value?.pk ??
            t?.value ??
            null;

        this.signingCertificatePk = pk ? String(pk) : null;

        if (this.verifySignature && this.metadataName) {
            void this.loadPreviewRowsByName(this.metadataName);
        }
    };

    private isSelected(key: string): boolean {
        return this.selectedKeys.includes(key);
    }

    private toggleKey(key: string, checked: boolean) {
        const cur = new Set(this.selectedKeys);
        if (checked) cur.add(key);
        else cur.delete(key);
        this.selectedKeys = Array.from(cur);
    }

    private toggleSelectAll(visibleKeys: string[], checked: boolean) {
        const cur = new Set(this.selectedKeys);
        if (checked) for (const k of visibleKeys) cur.add(k);
        else for (const k of visibleKeys) cur.delete(k);
        this.selectedKeys = Array.from(cur);
    }

    private getFilterQuery(): string {
        return (this.search ?? "").toLowerCase().trim();
    }

    private getVisibleRows(): Row[] {
        const q = this.getFilterQuery();
        if (!q) return this.rows;
        return this.rows.filter((r) => {
            const label = (r.label ?? "").toLowerCase();
            const eid = (r.entityIdText ?? "").toLowerCase();
            return label.includes(q) || eid.includes(q);
        });
    }

    private countSelected(kind: RowKind): number {
        if (!this.selectedKeys.length) return 0;
        const prefix = kind === "db" ? "db:" : "preview:";
        return this.selectedKeys.filter((k) => k.startsWith(prefix)).length;
    }

    private plannedActionFor(key: string): PlannedAction {
        return this.plannedByKey[key] ?? "none";
    }

    private plannedCount(action: PlannedAction): number {
        return Object.entries(this.plannedByKey).filter(([, v]) => v === action).length;
    }

    private renderCurrentBadge(row: Row): TemplateResult {
        return html`
            <span class="pf-c-label pf-m-outline" style="white-space:nowrap; display:inline-flex; align-items:center;">
                <span class="pf-c-label__content">${row.current}</span>
            </span>
        `;
    }

    private renderPlannedBadge(key: string): TemplateResult {
        const p = this.plannedActionFor(key);
        if (p === "none") {
            return html`
                <span class="pf-c-label pf-m-outline" style="white-space:nowrap; display:inline-flex; align-items:center;">
                    <span class="pf-c-label__content">—</span>
                </span>
            `;
        }
        const klass = p === "import" ? "pf-m-green" : "pf-m-red";
        const text = p === "import" ? msg("Import") : msg("Delete");
        return html`
            <span class="pf-c-label ${klass}" style="white-space:nowrap; display:inline-flex; align-items:center;">
                <span class="pf-c-label__content">${text}</span>
            </span>
        `;
    }

    private toDbRows(items: ManagedItem[]): Row[] {
        return items.map((it) => {
            // Prefer boolean overrides; fall back to legacy mode if present
            const vOv =
                it.verification_kp_override ??
                (it.verification_kp_mode ? String(it.verification_kp_mode).toLowerCase().trim() !== "inherit" : null);
            const eOv =
                it.encryption_kp_override ??
                (it.encryption_kp_mode ? String(it.encryption_kp_mode).toLowerCase().trim() !== "inherit" : null);
            const sOv =
                it.signing_kp_override ??
                (it.signing_kp_mode ? String(it.signing_kp_mode).toLowerCase().trim() !== "inherit" : null);

            return {
                kind: "db",
                key: `db:${it.uuid}`,
                uuid: it.uuid,
                label: String(it.name ?? it.entity_id ?? it.uuid),
                entity_id: String(it.entity_id ?? ""),
                entityIdText: String(it.entity_id ?? ""),
                current: "db",

                propertyMappingsOverride: !!it.property_mappings_override,
                propertyMappings: Array.isArray(it.property_mappings) ? it.property_mappings.map(String) : [],

                // SP panel uses override booleans
                verificationKpOverride: vOv === null ? false : !!vOv,
                encryptionKpOverride: eOv === null ? false : !!eOv,
                signingKpOverride: sOv === null ? false : !!sOv,

                // keep mode strings too (IdP panel uses these)
                verificationKpMode: it.verification_kp_mode ? String(it.verification_kp_mode) : null,
                encryptionKpMode: it.encryption_kp_mode ? String(it.encryption_kp_mode) : null,
                signingKpMode: it.signing_kp_mode ? String(it.signing_kp_mode) : null,

                freezeVerificationKp: !!it.freeze_verification_kp,
                freezeEncryptionKp: !!it.freeze_encryption_kp,
                freezeSigningKp: !!it.freeze_signing_kp,
            };
        });
    }

    private toPreviewRows(items: SAMLMetadataCatalogItem[]): Row[] {
        return items
            .filter((it) => (it.kind ?? []).includes(this.kind))
            .map((it) => {
                const entityId = String(it.entity_id);
                const label = String(it.display_name ?? it.entity_id);
                const current = (it.states?.metadata ?? "unknown") as CatalogState;

                return {
                    kind: "preview",
                    key: `preview:${entityId}`,
                    entity_id: entityId,
                    label,
                    entityIdText: entityId,
                    current,
                };
            });
    }

    private mergeRows(previewItems: SAMLMetadataCatalogItem[], dbItems: ManagedItem[]): Row[] {
        const previewByEid = new Map<string, Row>();
        for (const pv of this.toPreviewRows(previewItems)) {
            previewByEid.set(normEntityId(pv.entityIdText), pv);
        }

        const out: Row[] = [];

        // DB rows first; merge preview state into DB rows when entity_id matches
        for (const db of this.toDbRows(dbItems)) {
            const eid = normEntityId(db.entityIdText);
            const pv = previewByEid.get(eid);

            if (pv) {
                out.push({
                    ...db,
                    current: (pv.current ?? "unknown") as any,
                    previewEntityId: pv.entity_id ?? pv.entityIdText,
                });
                previewByEid.delete(eid);
            } else {
                out.push(db);
            }
        }

        // Remaining preview-only rows (new entries etc.)
        for (const pv of previewByEid.values()) out.push(pv);
        return out;
    }

    private pruneSelectionAndPlan(): void {
        const validKeys = new Set(this.rows.map((r) => r.key));
        this.selectedKeys = this.selectedKeys.filter((k) => validKeys.has(k));

        const nextPlanned: Record<string, PlannedAction> = {};
        for (const [k, v] of Object.entries(this.plannedByKey)) {
            if (validKeys.has(k) && v !== "none") nextPlanned[k] = v;
        }
        this.plannedByKey = nextPlanned;

        this.pruneLocalSettings();
    }

    private canEditLocalSettings(row: Row): boolean {
        if (row.kind !== "db") return false;
        return !!row.uuid;
    }

    private getRowLocalSettingsSummary(row: Row): RowLocalSettingsSummary {
        // PM override UI is SP-only. IdP has no PM override panel.
        if (this.kind !== "sp") return { mode: "inherit" };
        if (!this.canEditLocalSettings(row)) return { mode: "inherit" };

        const effectiveOverride = row.propertyMappingsOverride ?? false;
        const effectiveMappings = row.propertyMappings ?? [];

        if (!effectiveOverride) return { mode: "inherit" };
        if (effectiveMappings.length === 0) return { mode: "none" };
        return { mode: "set", count: effectiveMappings.length };
    }

    private renderLocalSettingsBadge(row: Row): TemplateResult {
        if (!this.canEditLocalSettings(row)) return html``;
        if (this.kind !== "sp") return html``;

        const summary = this.getRowLocalSettingsSummary(row);

        if (summary.mode === "inherit") {
            return html`
                <span class="pf-c-label pf-m-outline" style="white-space:nowrap;">
                    <span class="pf-c-label__content">${msg("PM: inherit")}</span>
                </span>
            `;
        }
        if (summary.mode === "none") {
            return html`
                <span class="pf-c-label pf-m-orange" style="white-space:nowrap;">
                    <span class="pf-c-label__content">${msg("PM: none")}</span>
                </span>
            `;
        }
        return html`
            <span class="pf-c-label pf-m-blue" style="white-space:nowrap;">
                <span class="pf-c-label__content">${msg("PM")}: ${summary.count}</span>
            </span>
        `;
    }

    private closeLocalSettings(): void {
        this.localSettingsOpen = false;
        this.localSettingsRowKey = null;
    }

    private openLocalSettings(row: Row): void {
        if (this.actionLoading) return;
        if (!this.canEditLocalSettings(row)) return;

        if (this.localSettingsOpen && this.localSettingsRowKey === row.key) {
            this.closeLocalSettings();
            return;
        }

        this.localSettingsRowKey = row.key;
        this.localSettingsOpen = true;
    }

    private pruneLocalSettings(): void {
        const validPreviewKeys = new Set(this.rows.filter((r) => r.kind === "preview").map((r) => r.key));
        const nextPreview: Record<string, SAMLSPImportLocalSettings> = {};
        for (const [k, v] of Object.entries(this.plannedLocalSettingsByKey)) {
            if (validPreviewKeys.has(k)) nextPreview[k] = v;
        }
        this.plannedLocalSettingsByKey = nextPreview;

        if (this.localSettingsRowKey) {
            const exists = this.rows.some((r) => r.key === this.localSettingsRowKey);
            if (!exists) this.closeLocalSettings();
        }
    }

    private rowByKey(key: string | null): Row | undefined {
        if (!key) return undefined;
        return this.rows.find((r) => r.key === key);
    }

    private buildDbKeyByEntityId(): Map<string, string> {
        const m = new Map<string, string>();
        for (const r of this.rows) {
            if (r.kind !== "db" || !r.uuid) continue;
            const eid = normEntityId(String(r.entityIdText ?? ""));
            if (!eid) continue;
            m.set(eid, `db:${r.uuid}`);
        }
        return m;
    }

    private countSelectedDeletable(): number {
        if (!this.selectedKeys.length) return 0;

        const dbByEid = this.buildDbKeyByEntityId();
        let n = 0;

        for (const k of this.selectedKeys) {
            if (k.startsWith("db:")) {
                n += 1;
                continue;
            }
            if (k.startsWith("preview:")) {
                const eid = normEntityId(k.slice("preview:".length));
                if (dbByEid.has(eid)) n += 1;
            }
        }
        return n;
    }

    private async listManaged(): Promise<ManagedItem[]> {
        if (this.kind === "sp") {
            const api = new ProvidersApi(DEFAULT_CONFIG);
            const all: ManagedItem[] = [];
            let page = 1;

            for (;;) {
                const res = await api.providersSamlspList({
                    provider: this.ownerPk,
                    pageSize: 100,
                    page,
                });

                for (const sp of res.results ?? []) {
                    all.push({
                        uuid: String((sp as any).uuid),
                        entity_id: String((sp as any).entityId ?? (sp as any).entity_id ?? ""),
                        name: String((sp as any).name ?? ""),
                        property_mappings_override: !!(
                            (sp as any).propertyMappingsOverride ?? (sp as any).property_mappings_override
                        ),
                        property_mappings: Array.isArray((sp as any).propertyMappings)
                            ? (sp as any).propertyMappings.map(String)
                            : Array.isArray((sp as any).property_mappings)
                              ? (sp as any).property_mappings.map(String)
                              : [],

                        // preferred booleans
                        verification_kp_override:
                            (sp as any).verificationKpOverride ?? (sp as any).verification_kp_override ?? null,
                        encryption_kp_override:
                            (sp as any).encryptionKpOverride ?? (sp as any).encryption_kp_override ?? null,
                        signing_kp_override: (sp as any).signingKpOverride ?? (sp as any).signing_kp_override ?? null,

                        // legacy mode strings (if present)
                        verification_kp_mode: (sp as any).verificationKpMode ?? (sp as any).verification_kp_mode ?? null,
                        encryption_kp_mode: (sp as any).encryptionKpMode ?? (sp as any).encryption_kp_mode ?? null,
                        signing_kp_mode: (sp as any).signingKpMode ?? (sp as any).signing_kp_mode ?? null,

                        freeze_verification_kp:
                            (sp as any).freezeVerificationKp ?? (sp as any).freeze_verification_kp ?? null,
                        freeze_encryption_kp:
                            (sp as any).freezeEncryptionKp ?? (sp as any).freeze_encryption_kp ?? null,
                        freeze_signing_kp: (sp as any).freezeSigningKp ?? (sp as any).freeze_signing_kp ?? null,
                    });
                }

                const next = (res as any).pagination?.next as number | null | undefined;
                if (!next) break;
                page = next;
            }

            return all;
        }

        if (this.kind === "idp") {
            const api = new SourcesApi(DEFAULT_CONFIG);
            const all: ManagedItem[] = [];
            let page = 1;

            for (;;) {
                const res = await api.sourcesSamlidpList({
                    source: this.ownerPk,
                    pageSize: 100,
                    page,
                });

                for (const idp of res.results ?? []) {
                    all.push({
                        uuid: String((idp as any).uuid),
                        entity_id: String((idp as any).entityId ?? (idp as any).entity_id ?? ""),
                        name: String((idp as any).name ?? ""),
                        property_mappings_override: !!(
                            (idp as any).propertyMappingsOverride ?? (idp as any).property_mappings_override
                        ),
                        property_mappings: Array.isArray((idp as any).propertyMappings)
                            ? (idp as any).propertyMappings.map(String)
                            : Array.isArray((idp as any).property_mappings)
                              ? (idp as any).property_mappings.map(String)
                              : [],

                        verification_kp_mode: (idp as any).verificationKpMode ?? (idp as any).verification_kp_mode ?? null,
                        encryption_kp_mode: (idp as any).encryptionKpMode ?? (idp as any).encryption_kp_mode ?? null,
                        signing_kp_mode: (idp as any).signingKpMode ?? (idp as any).signing_kp_mode ?? null,

                        freeze_verification_kp:
                            (idp as any).freezeVerificationKp ?? (idp as any).freeze_verification_kp ?? null,
                        freeze_encryption_kp:
                            (idp as any).freezeEncryptionKp ?? (idp as any).freeze_encryption_kp ?? null,
                        freeze_signing_kp: (idp as any).freezeSigningKp ?? (idp as any).freeze_signing_kp ?? null,
                    });
                }

                const next = (res as any).pagination?.next as number | null | undefined;
                if (!next) break;
                page = next;
            }

            return all;
        }

        return [];
    }

    private async loadDbRows(): Promise<void> {
        if (!this.ownerPk) return;
        this.dbLoading = true;
        try {
            const dbItems = await this.listManaged();

            // If we already have a preview open, re-fetch preview to keep merged state consistent.
            // Otherwise just show DB list.
            if (this.metadataName) {
                // keep signature meta as-is if preview fails
                try {
                    const resp = await catalogPreviewByName(
                        this.kind,
                        String(this.ownerPk),
                        this.metadataName,
                        this.catalogOpts,
                    );
                    this.signatureMeta = resp?.meta?.signature ?? this.signatureMeta;
                    this.rows = this.mergeRows(resp.items ?? [], dbItems);
                } catch {
                    this.rows = this.toDbRows(dbItems);
                }
            } else {
                this.rows = this.toDbRows(dbItems);
            }

            this.pruneSelectionAndPlan();
        } finally {
            this.dbLoading = false;
        }
    }

    private async loadPreviewRowsByName(metadataName: string): Promise<void> {
        if (!this.ownerPk) return;

        this.previewLoading = true;
        this.previewError = null;

        try {
            const resp = await catalogPreviewByName(
                this.kind,
                String(this.ownerPk),
                metadataName,
                this.catalogOpts,
            );
            this.signatureMeta = resp?.meta?.signature ?? null;

            const previewItems = resp.items ?? [];
            const dbItems = await this.listManaged();

            this.rows = this.mergeRows(previewItems, dbItems);

            // Auto-stage import:
            // - preview-only rows: unchanged/updated => import (new is user choice)
            // - merged DB rows: unchanged/updated => import (A policy)
            const nextPlanned: Record<string, PlannedAction> = { ...this.plannedByKey };
            for (const r of this.rows) {
                const hasPreview = r.kind === "preview" || !!r.previewEntityId;
                if (!hasPreview) continue;
                if (r.current !== "new") nextPlanned[r.key] = "import";
            }
            this.plannedByKey = nextPlanned;

            this.pruneSelectionAndPlan();
        } catch (e) {
            this.previewError = e instanceof Error ? e.message : String(e);
            showMessage({ level: MessageLevel.error, message: msg("Failed to preview metadata.") });
        } finally {
            this.previewLoading = false;
        }
    }

    private previewFromSelectedMetadata = async (): Promise<void> => {
        if (!this.metadataName) {
            showMessage({ level: MessageLevel.warning, message: msg("Select a metadata file.") });
            return;
        }
        await this.loadPreviewRowsByName(this.metadataName);
    };

    private stageSelected(action: PlannedAction): void {
        if (!this.selectedKeys.length) {
            showMessage({ level: MessageLevel.warning, message: msg("No rows selected.") });
            return;
        }

        const nextPlanned: Record<string, PlannedAction> = { ...this.plannedByKey };
        const dbByEid = this.buildDbKeyByEntityId();

        for (const key of this.selectedKeys) {
            const isPreview = key.startsWith("preview:");
            const isDb = key.startsWith("db:");

            if (action === "import") {
                // A policy: allow BOTH preview and DB
                if (isPreview || isDb) nextPlanned[key] = "import";
                continue;
            }

            if (action === "delete") {
                if (isDb) {
                    nextPlanned[key] = "delete";
                    continue;
                }
                if (isPreview) {
                    const eid = normEntityId(key.slice("preview:".length));
                    const dbKey = dbByEid.get(eid);
                    if (dbKey) nextPlanned[dbKey] = "delete";
                }
                continue;
            }

            if (action === "none") {
                if (isDb) delete nextPlanned[key];
                if (isPreview) {
                    delete nextPlanned[key];
                    const eid = normEntityId(key.slice("preview:".length));
                    const dbKey = dbByEid.get(eid);
                    if (dbKey) delete nextPlanned[dbKey];
                }
            }
        }

        this.plannedByKey = nextPlanned;
    }

    private resetPlan(): void {
        this.plannedByKey = {};
        this.plannedLocalSettingsByKey = {};
        showMessage({ level: MessageLevel.info, message: msg("Staged changes cleared.") });
    }

    private openProgress(label: string, total: number) {
        this.progressOpen = true;
        this.progressLabel = label;
        this.progressDone = 0;
        this.progressTotal = Math.max(0, total);
    }

    private bumpProgress(step = 1) {
        this.progressDone = Math.min(this.progressTotal, this.progressDone + step);
    }

    private closeProgress() {
        this.progressOpen = false;
        this.progressLabel = "";
        this.progressDone = 0;
        this.progressTotal = 0;
    }

    private resolveEntityIdForKey(key: string): string | null {
        if (key.startsWith("preview:")) return key.slice("preview:".length);

        if (key.startsWith("db:")) {
            const uuid = key.slice("db:".length);
            const row = this.rows.find((r) => r.kind === "db" && r.uuid === uuid);
            const eid = row?.previewEntityId ?? row?.entity_id ?? row?.entityIdText;
            const out = normEntityId(String(eid ?? ""));
            return out ? out : null;
        }

        return null;
    }

    private async applyChanges(): Promise<void> {
        const plannedImportKeys = Object.entries(this.plannedByKey)
            .filter(([, v]) => v === "import")
            .map(([k]) => k);

        const plannedDeleteKeys = Object.entries(this.plannedByKey)
            .filter(([k, v]) => v === "delete" && k.startsWith("db:"))
            .map(([k]) => k);

        const uuids = plannedDeleteKeys.map((k) => k.slice("db:".length));

        const entityIds: Array<{ key: string; entityId: string }> = [];
        for (const k of plannedImportKeys) {
            const eid = this.resolveEntityIdForKey(k);
            if (eid) entityIds.push({ key: k, entityId: eid });
        }

        if (!entityIds.length && !uuids.length) {
            showMessage({ level: MessageLevel.info, message: msg("No staged changes to apply.") });
            return;
        }

        if (entityIds.length && !this.metadataName) {
            showMessage({
                level: MessageLevel.error,
                message: msg("Select a metadata file before applying staged imports."),
            });
            return;
        }

        const totalSteps = entityIds.length + uuids.length;
        this.actionLoading = true;
        this.openProgress(msg("Applying changes…"), totalSteps);

        try {

// 1) Imports from preview (metadata)
if (entityIds.length) {
    for (const { key, entityId } of entityIds) {
    try {
      const ent = await catalogGetEntityByName(
        this.kind,
        String(this.ownerPk),
        this.metadataName!,
        entityId,
        this.catalogOpts,
      );

      const rowKey = `preview:${entityId}`;
      const localSettings =
        this.kind === "sp" ? this.plannedLocalSettingsByKey[rowKey] : undefined;

      await importSingleEntity(this.kind, this.ownerPk, ent.xml, localSettings);

      // 成功したら計画から外す
      const nextPlanned = { ...this.plannedByKey };
      delete nextPlanned[rowKey];
      this.plannedByKey = nextPlanned;

    } catch (e) {
      // ここがポイント：落とさず継続
      console.warn("Import skipped:", entityId, e);
      showMessage({
        level: MessageLevel.warning,
        message: msg(`Skipped import (not in selected metadata): ${entityId}`),
      });

      // “失敗したら staged を残す” のが自然（原因直したら再実行できる）
      // もし「自動で外したい」なら delete plannedByKey[rowKey] をここでやる
      continue;
    } finally {
      this.bumpProgress(1);
    }
  }
}

            // 2) Bulk delete DB rows
            if (uuids.length) {
                const chunks = chunk(uuids, 100);
                for (const part of chunks) {
                    await bulkDelete(this.kind, this.ownerPk, part);
                    this.bumpProgress(part.length);
                }

                const nextPlanned = { ...this.plannedByKey };
                for (const uuid of uuids) delete nextPlanned[`db:${uuid}`];
                this.plannedByKey = nextPlanned;

                this.rows = this.rows.filter((r) => !(r.kind === "db" && r.uuid && uuids.includes(r.uuid)));
            }

            showMessage({ level: MessageLevel.success, message: msg("Changes applied.") });
            await this.loadDbRows();
            this.dispatchEvent(new CustomEvent("ak-import-finished", { bubbles: true, composed: true }));
        } catch (e) {
            // eslint-disable-next-line no-console
            console.error(e);
            showMessage({ level: MessageLevel.error, message: msg("Failed to apply changes.") });
        } finally {
            this.actionLoading = false;
            this.closeProgress();
        }
    }

    public override async send(): Promise<void> {
        await this.applyChanges();
    }

    public override async connectedCallback(): Promise<void> {
        super.connectedCallback();
        await this.loadDbRows();
    }

    private renderProgress(): TemplateResult {
        if (!this.progressOpen || this.progressTotal <= 0) return nothing;
        const pct = Math.round((this.progressDone / this.progressTotal) * 100);

        return html`
            <div class="pf-c-progress" style="margin: 8px 0;">
                <div class="pf-c-progress__description">${this.progressLabel}</div>
                <div class="pf-c-progress__status" aria-hidden="true">
                    ${this.progressDone}/${this.progressTotal} (${pct}%)
                </div>
                <div
                    class="pf-c-progress__bar"
                    role="progressbar"
                    aria-valuenow=${pct}
                    aria-valuemin="0"
                    aria-valuemax="100"
                >
                    <div class="pf-c-progress__indicator" style="width: ${pct}%"></div>
                </div>
            </div>
        `;
    }

    private renderSignatureBanner(): TemplateResult {
        const sig = this.signatureMeta;
        if (!sig) return nothing;

        const status = String(sig.status ?? "").toLowerCase().trim();
        const isOk = status === "ok";
        const isWarn = status === "stale" || status === "unsigned" || status === "skipped";
        const variant = isOk ? "pf-m-success" : isWarn ? "pf-m-warning" : "pf-m-danger";

        const title = msg("Signature");
        const body = sig.message ?? status;

        const extra = [
            sig.metadata_name ? `Name=${sig.metadata_name}` : null,
            sig.metadata_id ? `ID=${sig.metadata_id}` : null,
            sig.valid_until ? `validUntil=${sig.valid_until}` : null,
        ]
            .filter(Boolean)
            .join(" · ");

        return html`
            <div class="pf-c-alert ${variant}" style="margin: 0;">
                <div class="pf-c-alert__title">${title}: ${status || "—"}</div>
                <div class="pf-c-alert__description">
                    <div>${body}</div>
                    ${extra
                        ? html`<div style="margin-top:4px; opacity:0.85; font-size: 12px;">${extra}</div>`
                        : nothing}
                </div>
            </div>
        `;
    }

    private onSPLocalSettingsSaved = (ev: CustomEvent<SPLocalSettingsSavedDetail>): void => {
        ev.stopPropagation();

        const { spUuid, applied } = ev.detail;

        // Modal uses "enabled" semantics (inherit vs force-disable)
        // It PATCHes *_kp_override booleans; we reflect that as:
        // enabled=true  => override=false (inherit)
        // enabled=false => override=true  (local override with null to disable)
        const toOverride = (enabled: boolean) => !enabled;

        this.rows = this.rows.map((r) =>
            r.kind === "db" && r.uuid === spUuid
                ? {
                      ...r,
                      propertyMappingsOverride: applied.propertyMappingsOverride,
                      propertyMappings: [...applied.propertyMappings],
                      verificationKpOverride: toOverride(applied.verificationKeyEnabled),
                      encryptionKpOverride: toOverride(applied.encryptionKeyEnabled),
                      signingKpOverride: toOverride(applied.signingKeyEnabled),
                  }
                : r,
        );

        this.closeLocalSettings();
    };

    private onIdpLocalSettingsSaved = (ev: CustomEvent<IDPLocalSettingsSavedDetail>): void => {
        ev.stopPropagation();

        const { idpUuid, applied } = ev.detail;

        const toMode = (enabled: boolean) => (enabled ? "inherit" : "none");

        this.rows = this.rows.map((r) =>
            r.kind === "db" && r.uuid === idpUuid
                ? {
                      ...r,
                      verificationKpMode: toMode(applied.verificationKeyEnabled),
                      encryptionKpMode: toMode(applied.encryptionKeyEnabled),
                      signingKpMode: toMode(applied.signingKeyEnabled),
                  }
                : r,
        );

        this.closeLocalSettings();
    };

    private onLocalSettingsCancelled = (ev: Event): void => {
        ev.stopPropagation();
        this.closeLocalSettings();
    };

    public override renderForm(): TemplateResult {
        const visible = this.getVisibleRows();

        const visibleKeys = visible.map((r) => r.key);
        const selectedVisibleCount = visibleKeys.filter((k) => this.isSelected(k)).length;

        const allVisibleSelected = visibleKeys.length > 0 && selectedVisibleCount === visibleKeys.length;
        const someVisibleSelected = selectedVisibleCount > 0 && !allVisibleSelected;

        queueMicrotask(() => {
            const el = this.selectAllRef.value;
            if (el) el.indeterminate = someVisibleSelected;
        });

        const selectedPreview = this.countSelected("preview");
        const selectedDb = this.countSelected("db");
        const deletableSelected = this.countSelectedDeletable();

        const stagedImport = this.plannedCount("import");
        const stagedDelete = this.plannedCount("delete");

        // A policy: allow Stage import for DB too
        const canStageImport = !this.actionLoading && selectedPreview + selectedDb > 0;
        const canStageDelete = !this.actionLoading && deletableSelected > 0;

        return html`
            <form class="pf-c-form pf-m-horizontal">
                <div style="display:flex; flex-direction:column; gap: 8px; margin-bottom: 10px;">
                    <div style="display:flex; gap: 12px; align-items:center; flex-wrap: wrap;">
                        <div style="flex: 1 1 420px; min-width: 280px;">
                            <ak-file-search-input
                                name="metadataName"
                                label=${msg("Metadata file")}
                                .usage=${AdminFileListUsageEnum.SamlMetadata}
                                .value=${this.metadataName ?? ""}
                                ?disabled=${this.actionLoading || this.previewLoading}
                                @ak-change=${(ev: CustomEvent) => {
                                    const v = (ev.detail?.value?.name ?? "").trim();
                                    this.metadataName = v || null;
                                    if (this.metadataName) void this.loadPreviewRowsByName(this.metadataName);
                                }}
                            ></ak-file-search-input>
                        </div>

                        <div style="flex: 0 0 auto; display:flex; align-items:center; gap: 12px; flex-wrap: wrap;">
                            <ak-switch-input
                                name="verifySignature"
                                label=${msg("Verify signature")}
                                ?checked=${this.verifySignature}
                                ?disabled=${this.actionLoading || this.previewLoading}
                                @change=${(ev: Event) => {
                                    this.verifySignature = !!(ev.target as HTMLInputElement | null)?.checked;
                                    if (this.metadataName) void this.loadPreviewRowsByName(this.metadataName);
                                }}
                                @ak-change=${(ev: CustomEvent) => {
                                    const d: any = ev.detail;
                                    if (typeof d?.value === "boolean") this.verifySignature = d.value;
                                    else this.verifySignature = !!(ev.target as HTMLInputElement | null)?.checked;
                                    if (this.metadataName) void this.loadPreviewRowsByName(this.metadataName);
                                }}
                            ></ak-switch-input>

                            <!-- IMPORTANT: ak-crypto-certificate-search must be inside a named ak-form-element-horizontal -->
     <ak-form-element-horizontal
       name="signingCertificate"
       label=${msg("Signing certificate (optional)")}
       style="margin:0; min-width: 320px;"
     >
                                <ak-crypto-certificate-search
                                    nokey
                                    singleton
                                    ?disabled=${this.actionLoading || this.previewLoading || !this.verifySignature}
                                    @input=${this.onSigningCertChanged}
                                    @ak-change=${this.onSigningCertChanged}
                                    @change=${this.onSigningCertChanged}
                                ></ak-crypto-certificate-search>
                            </ak-form-element-horizontal>
                        </div>

  <div
    style="
      flex: 0 0 auto;
      display:flex;
      align-items:center;
      gap: 8px;
      white-space: nowrap;
    "
  >
    <button
      type="button"
      class="pf-c-button pf-m-secondary"
      ?disabled=${this.actionLoading || this.previewLoading || !this.metadataName}
      @click=${this.previewFromSelectedMetadata}
    >
      ${msg("Preview")}
    </button>

    <button
      type="button"
      class="pf-c-button pf-m-primary"
      ?disabled=${!canStageImport}
      @click=${() => this.stageSelected("import")}
    >
      ${msg("Stage import")}
    </button>

    <button
      type="button"
      class="pf-c-button pf-m-danger"
      ?disabled=${!canStageDelete}
      @click=${() => this.stageSelected("delete")}
    >
      ${msg("Stage delete")}
    </button>

    <button
      type="button"
      class="pf-c-button pf-m-secondary"
      ?disabled=${this.actionLoading || stagedImport + stagedDelete === 0}
      @click=${this.resetPlan}
    >
      ${msg("Clear staged")}
    </button>
  </div>

                        <div style="margin-left:auto; font-size: 12px; opacity: 0.8; white-space: nowrap;">
                            ${msg("Target")}: ${this.ownerLabel} · ${msg("Kind")}: ${this.kind.toUpperCase()}
                        </div>
                    </div>

                    ${this.renderSignatureBanner()}

                    <div style="display:flex; gap: 10px; align-items:flex-end; flex-wrap: wrap;">
                        <div class="pf-c-form__group" style="margin:0; flex: 1 1 420px; min-width: 280px;">
                            <label class="pf-c-form__label">
                                <span class="pf-c-form__label-text">${msg("Search")}</span>
                            </label>
                            <div class="pf-c-form__group-control">
                                <input
                                    class="pf-c-form-control"
                                    type="search"
                                    placeholder=${msg("Filter by name or entity ID…")}
                                    .value=${this.search}
                                    @input=${(ev: Event) => (this.search = (ev.target as HTMLInputElement).value)}
                                />
                            </div>
                        </div>

                        <label class="pf-c-check" style="display:flex; align-items:center; gap:8px; margin:0;">
                            <input
                                ${ref(this.selectAllRef)}
                                class="pf-c-check__input"
                                type="checkbox"
                                .checked=${allVisibleSelected}
                                ?disabled=${visibleKeys.length === 0}
                                @change=${(ev: Event) => {
                                    const checked = (ev.target as HTMLInputElement).checked;
                                    this.toggleSelectAll(visibleKeys, checked);
                                }}
                            />
                            <span class="pf-c-check__label">${msg("Select all (filtered)")}</span>
                        </label>

                        <div style="font-size: 12px; opacity: 0.85; white-space: nowrap;">
                            ${msg("Selected")}: ${this.selectedKeys.length}
                            (${msg("preview")}: ${selectedPreview}, ${msg("db")}: ${selectedDb})
                            · ${msg("Staged")}: ${stagedImport + stagedDelete}
                            (${msg("import")}: ${stagedImport}, ${msg("delete")}: ${stagedDelete})
                        </div>
                    </div>

                    ${this.dbLoading || this.previewLoading ? html`<p style="margin:0;">${msg("Loading…")}</p>` : nothing}

                    ${this.previewError
                        ? html`
                              <div class="pf-c-alert pf-m-danger" style="margin:0;">
                                  <div class="pf-c-alert__title">${msg("Preview error")}</div>
                                  <div class="pf-c-alert__description">${this.previewError}</div>
                              </div>
                          `
                        : nothing}

                    ${this.renderProgress()}
                </div>

                <div
                    style="
                        max-height: 60vh;
                        overflow: auto;
                        border: 1px solid var(--pf-global--BorderColor--100);
                        border-radius: 6px;
                        padding: 4px;
                    "
                >
                    ${visible.length === 0
                        ? html`<p style="margin: 6px;">${msg("No entries found.")}</p>`
                        : html`
                              <div style="display:grid; gap:4px;">
                                  ${visible.map((row) => {
                                      const checked = this.isSelected(row.key);
                                      const label = String(row.label ?? "");
                                      const eid = String(row.entityIdText ?? "");
                                      const localEditable = this.canEditLocalSettings(row);
                                      const isPanelOpen =
                                          this.localSettingsOpen &&
                                          this.localSettingsRowKey === row.key &&
                                          !!row.uuid;

                                      return html`
                                          <div style="display:flex; flex-direction:column; gap: 0;">
                                              <div
                                                  style="
                                                      display:flex;
                                                      align-items:center;
                                                      gap: 10px;
                                                      padding: 6px 8px;
                                                      min-height: 46px;
                                                      border: 1px solid var(--pf-global--BorderColor--200);
                                                      border-radius: 6px;
                                                      background: var(--pf-global--BackgroundColor--100);
                                                  "
                                              >
                                                  <label
                                                      class="pf-c-check pf-m-standalone"
                                                      style="margin:0; flex:0 0 auto; line-height:0; align-self:center;"
                                                  >
                                                      <input
                                                          class="pf-c-check__input"
                                                          type="checkbox"
                                                          style="margin:0;"
                                                          .checked=${checked}
                                                          @change=${(ev: Event) => {
                                                              const isChecked = (ev.target as HTMLInputElement).checked;
                                                              this.toggleKey(row.key, isChecked);
                                                          }}
                                                      />
                                                  </label>

                                                  <span style="flex: 0 0 auto; display:inline-flex; align-items:center;">
                                                      ${this.renderCurrentBadge(row)}
                                                  </span>

                                                  <div
                                                      style="
                                                          flex: 1 1 auto;
                                                          min-width: 0;
                                                          display:flex;
                                                          flex-direction:column;
                                                          gap:2px;
                                                      "
                                                  >
                                                      <div
                                                          style="
                                                              min-width:0;
                                                              overflow:hidden;
                                                              text-overflow:ellipsis;
                                                              white-space:nowrap;
                                                              font-size:13px;
                                                              line-height:1.2;
                                                              font-weight: 500;
                                                          "
                                                          title=${label}
                                                      >
                                                          ${label}
                                                      </div>
                                                      <div
                                                          style="
                                                              min-width:0;
                                                              overflow:hidden;
                                                              text-overflow:ellipsis;
                                                              white-space:nowrap;
                                                              font-size:12px;
                                                              line-height:1.2;
                                                              opacity:0.75;
                                                              font-family: var(--pf-global--FontFamily--monospace);
                                                          "
                                                          title=${eid}
                                                      >
                                                          ${eid}
                                                      </div>
                                                  </div>

                                                  ${localEditable
                                                      ? html`
                                                            <span style="flex:0 0 auto;">
                                                                ${this.renderLocalSettingsBadge(row)}
                                                            </span>
                                                            <button
                                                                type="button"
                                                                class="pf-c-button pf-m-link pf-m-inline"
                                                                style="flex:0 0 auto;"
                                                                ?disabled=${this.actionLoading}
                                                                @click=${() => this.openLocalSettings(row)}
                                                            >
                                                                ${msg("Local settings")}
                                                            </button>
                                                        `
                                                      : nothing}

                                                  <span style="flex: 0 0 auto; display:inline-flex; align-items:center;">
                                                      ${this.renderPlannedBadge(row.key)}
                                                  </span>
                                              </div>

                                              ${isPanelOpen
                                                  ? this.kind === "sp"
                                                      ? html`
                                                            <div
                                                                style="
                                                                    margin-top: 6px;
                                                                    border: 1px solid var(--pf-global--BorderColor--100);
                                                                    border-radius: 6px;
                                                                    background: var(--pf-global--BackgroundColor--100);
                                                                    padding: 10px 12px;
                                                                "
                                                            >
                                                                <ak-saml-sp-db-local-settings-modal
                                                                    .open=${true}
                                                                    .providerPk=${this.ownerPk}
                                                                    .spUuid=${row.uuid ?? ""}
                                                                    .rowLabel=${row.label ?? ""}
                                                                    .rowEntityId=${row.entityIdText ?? ""}
                                                                    .propertyMappingsOverride=${row.propertyMappingsOverride ?? false}
                                                                    .propertyMappings=${row.propertyMappings ?? []}
                                                                    .verificationKpOverride=${row.verificationKpOverride ?? false}
                                                                    .encryptionKpOverride=${row.encryptionKpOverride ?? false}
                                                                    .signingKpOverride=${row.signingKpOverride ?? false}
                                                                    .disabled=${this.actionLoading}
                                                                    @ak-saml-sp-local-settings-saved=${this.onSPLocalSettingsSaved}
                                                                    @ak-saml-sp-local-settings-cancelled=${this.onLocalSettingsCancelled}
                                                                    @ak-saml-sp-local-settings-closed=${this.onLocalSettingsCancelled}
                                                                ></ak-saml-sp-db-local-settings-modal>
                                                            </div>
                                                        `
                                                      : html`
                                                            <div
                                                                style="
                                                                    margin-top: 6px;
                                                                    border: 1px solid var(--pf-global--BorderColor--100);
                                                                    border-radius: 6px;
                                                                    background: var(--pf-global--BackgroundColor--100);
                                                                    padding: 10px 12px;
                                                                "
                                                            >
                                                                <ak-saml-idp-db-local-settings-modal
                                                                    .open=${true}
                                                                    .sourcePk=${this.ownerPk}
                                                                    .idpUuid=${row.uuid ?? ""}
                                                                    .rowLabel=${row.label ?? ""}
                                                                    .rowEntityId=${row.entityIdText ?? ""}
                                                                    .verificationKpMode=${row.verificationKpMode ?? null}
                                                                    .encryptionKpMode=${row.encryptionKpMode ?? null}
                                                                    .signingKpMode=${row.signingKpMode ?? null}
                                                                    .disabled=${this.actionLoading}
                                                                    @ak-saml-idp-local-settings-saved=${this.onIdpLocalSettingsSaved}
                                                                    @ak-saml-idp-local-settings-cancelled=${this.onLocalSettingsCancelled}
                                                                    @ak-saml-idp-local-settings-closed=${this.onLocalSettingsCancelled}
                                                                ></ak-saml-idp-db-local-settings-modal>
                                                            </div>
                                                        `
                                                  : nothing}
                                          </div>
                                      `;
                                  })}
                              </div>
                          `}
                </div>
            </form>
        `;
    }
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-saml-snapshot-import": SAMLSnapshotImportForm;
    }
}

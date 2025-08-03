import { HorizontalLightComponent } from "./HorizontalLightComponent.js";

import { html } from "lit";
import { customElement, property } from "lit/decorators.js";
import { ifDefined } from "lit/directives/if-defined.js";

@customElement("ak-textarea-input")
export class AkTextareaInput extends HorizontalLightComponent<string> {
    @property({ type: String, reflect: true })
    public value = "";

    #inputListener = (ev: InputEvent) => {
        this.value = (ev.target as HTMLInputElement).value;
    };

    public override renderControl() {
        const code = this.inputHint === "code";

        // Prevent the leading spaces added by Prettier's whitespace algo
        // prettier-ignore
        return html`<textarea
            id=${ifDefined(this.fieldID)}
            @input=${this.#inputListener}
            class="pf-c-form-control"
            ?required=${this.required}
            name=${this.name}
            autocomplete=${ifDefined(code ? "off" : undefined)}
            spellcheck=${ifDefined(code ? "false" : undefined)}
        >${this.value !== undefined ? this.value : ""}</textarea
        > `;
    }
}

export default AkTextareaInput;

declare global {
    interface HTMLElementTagNameMap {
        "ak-textarea-input": AkTextareaInput;
    }
}

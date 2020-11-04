import {Injectable} from '@angular/core';
import {ReplaySubject} from 'rxjs';

@Injectable({
    providedIn: 'root'
})
export class OtpService {
    module: typeof import('slauth');

    ready = new ReplaySubject<boolean>(1);

    constructor() {
        if (this.isWebAssemblySupported()) {
            // @ts-ignore
            import('slauth').then(module => {
                this.module = module;
                this.ready.next(!!this.module);
            });
        }
    }

    isWebAssemblySupported(): boolean {
        try {
            if (typeof WebAssembly === 'object'
                && typeof WebAssembly.instantiate === 'function') {
                const module = new WebAssembly.Module(Uint8Array.of(0x0, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00));
                if (module instanceof WebAssembly.Module) {
                    return new WebAssembly.Instance(module) instanceof WebAssembly.Instance;
                }
            }
        } catch (e) {
        }
        return false;
    }
}

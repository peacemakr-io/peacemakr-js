interface Persister {
    set(key: string, value: string): void;
    get(key: string): string;
    exists(key: string): boolean;
}

// *****WARNING*****: DO NOT USE LocalStoragePersister for any purpose other than testing locally on browser.
class LocalStoragePersister implements Persister {
    set(key: string, value: string): void {
        localStorage.setItem(key, value);
    }
    get(key: string): string {
        let item = localStorage.getItem(key);
        if (item === null) {
            return "";
        }
        return item;
    }
    exists(key: string): boolean {
        return localStorage.getItem(key) !== null;
    }
}

export {Persister, LocalStoragePersister};

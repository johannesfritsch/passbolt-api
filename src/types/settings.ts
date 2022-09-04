export interface Settings {
    app: App;
    passbolt: Passbolt;
}

interface App {
    debug: boolean;
    image_storage: {
        public_path: string;
    };
    server_timezone: string;
    session_timeout: number;
    url: string;
    version: Version;
}

interface Version {
    name: string;
    number: string;
}

interface Passbolt {
    edition: string;
    plugins: {};
}
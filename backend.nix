{ pkgs, naersk }: 
let
    naersk-lib = pkgs.callPackage naersk {};
in {
    skattemelding = naersk-lib.buildPackage {
        src = ./.;
        nativeBuildInputs = with pkgs; [ openssl pkg-config ];
    };

    shell = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [ openssl pkg-config ];
        buildInputs = with pkgs; [ 
            (rust-bin.nightly.latest.default.override {
                extensions = [ "rust-src" ];
            })
            cargo-edit
            cargo-watch
            openssl # Needed to build the app.
        ];
    };
}
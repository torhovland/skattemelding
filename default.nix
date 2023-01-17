{ dockerTools, writeShellScriptBin, cacert, skattemelding }: {
    image = dockerTools.buildLayeredImage {
        name = "gcr.io/skattemelding/skattemelding";
        tag = "latest";
        contents = with skattemelding; [ 
            backend.skattemelding 
        ];

        config = {
            Cmd = [ "/bin/skattemelding" ];
            Env = [ 
                "ENVIRONMENT=production" 
            ];
        };
    };

    dev = writeShellScriptBin "dev" ''
        rm -rf ./node_modules
        export PATH="${skattemelding.frontend.nodeDependencies}/bin:$PATH"
        nix develop --command npx concurrently \
            -n FE,BE \
            -c green,red \
            "cd backend && cargo run"
        '';
}

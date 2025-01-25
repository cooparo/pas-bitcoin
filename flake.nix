{
  description = "Python bitcoinlib Flake";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

  outputs =
    inputs:
    let
      system = "x86_64-linux";
      pkgs = inputs.nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          bitcoin
          libbitcoin-explorer

          (python312.withPackages (
            p: with p; [
              ecdsa
              bitcoinlib
              base58
            ]
          ))
        ];
      };
    };
}

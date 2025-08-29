# Replace /content/diversevul with your repo/code folder
!syft dir:/content/diversevul -o json > {SBOM_PATH}
print(f"✅ SBOM generated at {SBOM_PATH}")

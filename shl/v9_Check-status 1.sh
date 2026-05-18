#!/usr/bin/env bash

# Script partage avec autorisation par Karim S.

hostname=$(hostname)
output="${hostname}.html"
uptime_info=$(uptime -p)

echo "=========================================="
echo "🔍 Correction du rapport (v9)..."
echo "📄 Fichier : $output"
echo "=========================================="

# Fonction de vérification standard
check_status() {
    echo -n "⏳ Vérification : $2... "
    if eval "$1" >/dev/null 2>&1; then
        echo "✅ OK"
        echo "<tr class='success'><td>$2</td><td>✅ OK</td></tr>" >> "$output"
    else
        echo "❌ Erreur"
        echo "<tr class='danger'><td>$2</td><td>❌ Erreur / Non installé</td></tr>" >> "$output"
    fi
}

# Fonction avec version
check_version() {
    local cmd_check="$1"
    local label="$2"
    local cmd_version="$3"

    echo -n "⏳ Vérification : $label... "
    if eval "$cmd_check" >/dev/null 2>&1; then
        local version=$(eval "$cmd_version")
        echo "✅ OK ($version)"
        echo "<tr class='success'><td>$label</td><td>✅ OK <br><small style='color:#555;'><i>Version : $version</i></small></td></tr>" >> "$output"
    else
        echo "❌ Erreur"
        echo "<tr class='danger'><td>$label</td><td>❌ Erreur / Non installé</td></tr>" >> "$output"
    fi
}

# --- 1. GÉNÉRATION DE L'ENTÊTE ---
cat <<EOF > "$output"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: sans-serif; margin: 40px; background: #f0f2f5; }
        .container { max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #1a73e8; border-bottom: 2px solid #1a73e8; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        th { background: #f8f9fa; }
        .success { border-left: 5px solid #28a745; background-color: #fafffa; }
        .danger { border-left: 5px solid #dc3545; background-color: #fffafb; }
        details { margin-top: 20px; background: #eee; padding: 10px; border-radius: 5px; }
        summary { font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport de contrôle Post-Installation</h1>
        <p><b>Machine :</b> $hostname<br>
        <b>Date :</b> $(date '+%d/%m/%Y %H:%M:%S')<br>
        <b>Uptime :</b> $uptime_info</p>
        <table>
            <tr><th>Composant / Étape</th><th>État</th></tr>
EOF

# --- 2. EXÉCUTION DES TESTS (On écrit directement dans le tableau ouvert) ---

check_status "dnf repolist | grep -q epel" "Dépôt EPEL"
check_status "dnf repolist | grep -q docker-ce" "Dépôt Docker CE"
check_status "dnf repolist | grep -q cuda-rhel" "Dépôt NVIDIA CUDA"
check_status "dnf repolist | grep -q crb" "Dépôt CRB"
check_status "systemctl is-active --quiet haveged" "Service Haveged"
check_status "command -v realmd" "Utilitaire Realmd"
check_status "mokutil --sb-state | grep -q 'enabled'" "Secure Boot"
check_version "rpm -q docker-ce" "Docker Engine" "docker --version | awk '{print \$3}' | tr -d ','"
check_status "systemctl is-active --quiet docker" "Service Docker"
check_version "docker compose version" "Docker Compose" "docker compose version --short"
check_version "nvidia-smi" "Pilote NVIDIA" "nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -n 1"
check_status "rpm -q nvidia-container-toolkit" "NVIDIA Toolkit"

# --- 3. FERMETURE DU TABLEAU ET AJOUT DU FSTAB ---
echo "        </table>" >> "$output"

echo "⏳ Traitement des montages fstab..."
cat <<EOF >> "$output"
        <details>
            <summary>📂 Afficher les points de montage (/etc/fstab)</summary>
            <table>
                <tr><th>Point de montage</th><th>État</th></tr>
EOF

# Lecture du fstab sécurisée
while read -r dev mp type opt dump pass; do
    # On saute les commentaires et les trucs inutiles
    [[ "$dev" == "#"* || -z "$dev" || "$type" == "swap" || "$mp" == "none" ]] && continue
    
    if mountpoint -q "$mp"; then
        echo "<tr class='success'><td>$mp ($type)</td><td>✅ Actif</td></tr>" >> "$output"
    else
        echo "<tr class='danger'><td>$mp ($type)</td><td>❌ NON MONTÉ</td></tr>" >> "$output"
    fi
done < /etc/fstab

# --- 4. FERMETURE FINALE ---
cat <<EOF >> "$output"
            </table>
        </details>
    </div>
</body>
</html>
EOF

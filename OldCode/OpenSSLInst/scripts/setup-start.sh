# Verzeichnis erstellen
mkdir -p /opt/openssl-3.6.0/scripts

# Alle Scripte speichern
for script in activate.sh clean_old_install.sh install_benchmark_tools.sh install_openssl3.6_legacy_full.sh live_monitor.sh openssl_benchmark_epyc.sh test_legacy_compatibility.sh; do
    # Hier den entsprechenden Inhalt für jedes Script einfügen
    chmod +x "/opt/openssl-3.6.0/scripts/${script}"
done

# Symlink für einfachen Zugriff
ln -sf /opt/openssl-3.6.0/scripts/activate.sh /opt/openssl-3.6.0/activate

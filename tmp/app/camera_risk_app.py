import sys
from typing import List, Sequence

from db import Database
from feeds import update_from_kev, update_from_nvd, update_epss_for_all_cves
from risk import CameraRisk, VulnerabilityRisk, compute_all_risks


# ----------------------------------------------------------------------
# Helpers affichage
# ----------------------------------------------------------------------


def _hrule(char: str = "-", width: int = 80) -> None:
    print(char * width)


def print_table(headers: Sequence[str], rows: Sequence[Sequence[str]], max_width: int = 120) -> None:
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = min(max(col_widths[i], len(cell)), max_width // len(headers))

    def format_row(values: Sequence[str]) -> str:
        return " | ".join(
            v[:w].ljust(w) for v, w in zip(values, col_widths, strict=False)
        )

    print(format_row(headers))
    print("-+-".join("-" * w for w in col_widths))
    for r in rows:
        print(format_row(r))


# ----------------------------------------------------------------------
# Actions métiers
# ----------------------------------------------------------------------


def action_update_feeds(db: Database) -> None:
    print("\n[1/3] Récupération des CVE NVD liés aux caméras (mot-clé 'camera')...")
    try:
        update_from_nvd(db)
        print("   OK NVD.")
    except Exception as exc:  # pragma: no cover - robustesse I/O
        print(f"   ERREUR NVD: {exc}")

    print("\n[2/3] Récupération du catalogue CISA KEV...")
    try:
        update_from_kev(db)
        print("   OK KEV.")
    except Exception as exc:  # pragma: no cover
        print(f"   ERREUR KEV: {exc}")

    print("\n[3/3] Récupération des scores EPSS pour les CVE en base...")
    try:
        update_epss_for_all_cves(db)
        print("   OK EPSS.")
    except Exception as exc:  # pragma: no cover
        print(f"   ERREUR EPSS: {exc}")

    print("\nSynchronisation des données de vulnérabilités terminée.\n")


def action_browse_cameras(db: Database) -> None:
    while True:
        search = input(
            "\nFiltre de recherche (vendor / produit, vide pour tout, 'q' pour retour): "
        ).strip()
        if search.lower() == "q":
            return

        offset = 0
        page_size = 20

        while True:
            cameras = db.list_cameras(search=search or None, limit=page_size, offset=offset)
            if not cameras:
                if offset == 0:
                    print("Aucune caméra trouvée avec ce filtre.")
                else:
                    print("Pas d'autres résultats.")
                break

            rows: List[List[str]] = []
            for cam in cameras:
                rows.append(
                    [
                        str(cam["id"]),
                        cam["vendor"],
                        cam["product"],
                        cam["version"] or "-",
                        "oui" if cam["is_camera"] else "inconnu",
                    ]
                )

            print()
            _hrule()
            print("Caméras connues (page offset =", offset, ")")
            _hrule()
            print_table(
                ["ID", "Vendor", "Produit", "Version", "Est caméra ?"],
                rows,
            )

            print("\nOptions: [n] page suivante, [p] page précédente, [a] ajouter à \"mes caméras\", [q] retour recherche.")
            choice = input("> ").strip().lower()
            if choice == "n":
                offset += page_size
            elif choice == "p":
                offset = max(0, offset - page_size)
            elif choice == "a":
                cam_id_str = input("ID de la caméra à ajouter à vos équipements: ").strip()
                if not cam_id_str:
                    continue
                try:
                    cam_id = int(cam_id_str)
                except ValueError:
                    print("ID invalide.")
                    continue
                nickname = input("Nom / emplacement (optionnel, ex: 'Entrée bureau'): ").strip() or None
                try:
                    db.add_user_camera(camera_id=cam_id, nickname=nickname)
                    print("Caméra ajoutée à vos équipements.")
                except Exception as exc:  # pragma: no cover
                    print(f"Erreur lors de l'ajout: {exc}")
            elif choice == "q":
                break
            else:
                print("Choix non reconnu.")


def action_manage_user_cameras(db: Database) -> None:
    while True:
        user_cams = db.list_user_cameras()
        if not user_cams:
            print("\nVous n'avez encore sélectionné aucune caméra.")
        else:
            rows: List[List[str]] = []
            for uc in user_cams:
                display_name = uc["user_nickname"] or ""
                rows.append(
                    [
                        str(uc["user_camera_id"]),
                        uc["vendor"],
                        uc["product"],
                        uc["version"] or "-",
                        display_name,
                    ]
                )
            print()
            _hrule()
            print("Vos caméras sélectionnées")
            _hrule()
            print_table(
                ["ID sélection", "Vendor", "Produit", "Version", "Nom / emplacement"],
                rows,
            )

        print("\nOptions: [s]upprimer une sélection, [q] retour menu principal.")
        choice = input("> ").strip().lower()
        if choice == "q":
            return
        if choice == "s":
            sel = input("ID de sélection à supprimer: ").strip()
            if not sel:
                continue
            try:
                sel_id = int(sel)
            except ValueError:
                print("ID invalide.")
                continue
            db.remove_user_camera(sel_id)
        else:
            print("Choix non reconnu.")


def _format_vuln_row(v: VulnerabilityRisk) -> List[str]:
    kev_flag = "oui" if v.in_kev else "non"
    if v.in_kev and v.kev_ransomware:
        kev_flag = "oui (ransomware)"
    cvss = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "-"
    epss = f"{v.epss:.3f}" if v.epss is not None else "-"
    cwes = ", ".join(v.cwe_ids) if v.cwe_ids else "-"
    summary = (v.summary or "").strip().replace("\n", " ")
    if len(summary) > 80:
        summary = summary[:77] + "..."
    return [
        v.cve_id,
        cvss,
        v.cvss_severity or "-",
        epss,
        kev_flag,
        f"{v.risk_score:5.1f}",
        v.risk_level,
        cwes,
        summary or "-",
    ]


def action_show_dashboard(db: Database) -> None:
    cams, summary = compute_all_risks(db)
    print()
    _hrule("=")
    print("TABLEAU DE BORD — RISQUE SÉCURITÉ CAMÉRAS IoT")
    _hrule("=")

    if not cams:
        print("Aucune caméra sélectionnée. Ajoutez d'abord vos caméras via le menu.")
        return

    print(
        f"Caméras suivies : {summary.total_devices}  |  "
        f"Vulnérabilités totales : {summary.total_vulnerabilities}  |  "
        f"Dans KEV (exploitées) : {summary.total_kev}"
    )
    print(
        f"Score moyen par caméra : {summary.avg_device_risk:5.1f}  |  "
        f"Score maximal : {summary.max_device_risk:5.1f}"
    )
    _hrule()

    for cam in cams:
        title = f"{cam.vendor} {cam.product}"
        if cam.version:
            title += f" ({cam.version})"
        if cam.nickname:
            title += f" — {cam.nickname}"

        kev_count = sum(1 for v in cam.vulnerabilities if v.in_kev)

        print(f"\nCaméra #{cam.user_camera_id}: {title}")
        print(
            f"  Risque appareil : {cam.device_risk_score:5.1f} ({cam.device_risk_level})  |  "
            f"Vulnérabilités : {len(cam.vulnerabilities)}  |  "
            f"Dans KEV : {kev_count}"
        )

        if not cam.vulnerabilities:
            print("  Aucune vulnérabilité connue pour cette caméra (dans le périmètre actuel).")
            continue

        rows = [_format_vuln_row(v) for v in sorted(cam.vulnerabilities, key=lambda x: x.risk_score, reverse=True)]
        # Limiter l'affichage pour garder le tableau lisible
        max_rows = 15
        display_rows = rows[:max_rows]

        print_table(
            [
                "CVE",
                "CVSS",
                "Sev.",
                "EPSS",
                "KEV",
                "Score",
                "Niveau",
                "CWE",
                "Résumé",
            ],
            display_rows,
        )
        if len(rows) > max_rows:
            print(f"... {len(rows) - max_rows} vulnérabilités supplémentaires non affichées.")


# ----------------------------------------------------------------------
# Boucle principale CLI
# ----------------------------------------------------------------------


def main() -> None:
    db = Database()

    while True:
        print("\n=== Analyse de risque caméras IoT ===")
        print("1) Mettre à jour les données (NVD / KEV / EPSS)")
        print("2) Parcourir les caméras connues et en ajouter à mes équipements")
        print("3) Gérer mes caméras sélectionnées")
        print("4) Afficher le tableau de bord de risque")
        print("0) Quitter")

        choice = input("> ").strip()
        if choice == "1":
            action_update_feeds(db)
        elif choice == "2":
            action_browse_cameras(db)
        elif choice == "3":
            action_manage_user_cameras(db)
        elif choice == "4":
            action_show_dashboard(db)
        elif choice == "0":
            print("Au revoir.")
            db.close()
            sys.exit(0)
        else:
            print("Choix non reconnu.")


if __name__ == "__main__":
    main()


import os
import sys

from flask import Flask, render_template, request

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
BACKEND_PATH = os.path.join(PROJECT_ROOT, "backend")

sys.path.append(PROJECT_ROOT)
sys.path.append(BACKEND_PATH)

# --- IMPORTS BACKEND (désactivés pour l’instant) ---
# from debate.xxx import run_debate
# from semantics.xxx import run_semantic
# from internet_sources.xxx import run_sources

app = Flask(
    __name__,
    # IMPORTANT: app.py est dans frontend/, donc templates/static doivent être relatifs à ce dossier
    template_folder="frontend/public/templates",
    static_folder="frontend/public/static",
)

# Résultats “vides” mais structurés pour éviter tout crash dans le template
EMPTY_RESULTS = {
    "semantic": {
        "title": "Modèle sémantique",
        "decision": "INCERTAIN",
        "confidence": 0.0,
        "arguments": [],
    },
    "web": {
        "title": "Modèle sources Internet",
        "decision": "INCERTAIN",
        "confidence": 0.0,
        "arguments": [],
        "sources": [],
    },
    "debate": {
        "title": "Débat LLM (pro/contre)",
        "decision": "INCERTAIN",
        "confidence": 0.0,
        "arguments": [],
        "transcript": [],
    },
}


def decision_class(decision: str) -> str:
    return {
        "OK": "ok",
        "SUSPECT": "warn",
        "FAKE": "bad",
        "INCERTAIN": "neutral",
    }.get((decision or "").upper(), "neutral")


@app.route("/", methods=["GET", "POST"])
def index():
    input_text = ""
    results = None
    error = None

    if request.method == "POST":
        input_text = (request.form.get("text") or "").strip()

        # Pour l’instant: ne PAS appeler les modèles.
        # On renvoie un résultat structuré “vide” pour que le template affiche proprement.
        results = EMPTY_RESULTS

        # Quand tu réactiveras, fais un try/except par modèle, ex:
        # try:
        #     results["debate"] = run_debate(input_text)
        # except Exception as e:
        #     error = f"Debate model error: {e}"

    return render_template(
        "index.html",
        input_text=input_text,
        results=results,
        error=error,
        decision_class=decision_class,
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
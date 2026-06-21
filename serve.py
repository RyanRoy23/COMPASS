"""Point d'entrée pour lancer l'interface web."""
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "nis2_analyzer.web.app:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )

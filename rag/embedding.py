"""Load and cache the local embedding model used by optional vector retrieval. Honor configured offline mode and explicit model paths."""

import os
import glob
from typing import Optional

from .logging_config import get_logger
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

logger = get_logger(__name__)

def _apply_offline_mode():
    """Apply environment settings restricting model access to local files."""
    try:
        import config
        if getattr(config, "HF_HUB_OFFLINE", False):
            os.environ["HF_HUB_OFFLINE"] = "1"
            os.environ["TRANSFORMERS_OFFLINE"] = "1"
            logger.info("HF_HUB_OFFLINE mode enabled - no network requests to HuggingFace")
    except ImportError:
        pass

_apply_offline_mode()

def get_model_config():
    """Read local embedding settings from configuration."""
    try:
        import config
        model_name = getattr(config, "EMBEDDING_MODEL_CPU", "BAAI/bge-base-en-v1.5")
        local_path = getattr(config, "LOCAL_MODEL_PATH", None)
        offline_mode = getattr(config, "HF_HUB_OFFLINE", False)
        return model_name, local_path, offline_mode
    except ImportError:
        return "BAAI/bge-base-en-v1.5", None, False

class EmbeddingManager:
    """Manage an optional cached embedding model."""

    def __init__(
        self,
        model_name: str = None,
        device: str = "cpu",
        local_path: Optional[str] = None,
        offline_mode: bool = None
    ):
        """Init."""
        
        if model_name is None:
            model_name, config_local_path, config_offline = get_model_config()
            if local_path is None and config_local_path:
                local_path = config_local_path
            if offline_mode is None:
                offline_mode = config_offline

        self.model_name = model_name
        self.device = device
        self._embedding = None
        self._model_path = local_path
        self.offline_mode = offline_mode

        if self.offline_mode:
            os.environ["HF_HUB_OFFLINE"] = "1"
            os.environ["TRANSFORMERS_OFFLINE"] = "1"

    def _get_default_model_path(self) -> str:
        """Resolve the default local model directory."""
        
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_dir, "models", "rag_embeddings")

    def _get_model_folder_name(self) -> str:
        """Derive a filesystem-safe model directory name."""
        # BAAI/bge-small-en-v1.5 -> BAAI--bge-small-en-v1.5
        return self.model_name.replace("/", "--")

    def _auto_detect_local_path(self) -> Optional[str]:
        """Look for an existing local model directory."""
        
        if self._model_path and os.path.exists(self._model_path):
            return self._model_path

        default_path = self._get_default_model_path()
        folder_name = self._get_model_folder_name()
        auto_path = os.path.join(default_path, folder_name)

        if os.path.exists(auto_path):
            logger.info(f"Auto-detected local model path: {auto_path}")
            return auto_path

        simple_name = self.model_name.split("/")[-1] if "/" in self.model_name else self.model_name
        simple_path = os.path.join(default_path, simple_name)
        if os.path.exists(simple_path):
            logger.info(f"Auto-detected local model path: {simple_path}")
            return simple_path

        return None

    def _get_full_model_path(self) -> str:
        """Resolve the configured model path."""
        local_path = self._auto_detect_local_path()
        if local_path:
            return local_path
        
        return self.model_name

    def _is_model_cached(self) -> bool:
        """Check whether the model is available locally."""
        model_path = self._get_full_model_path()

        if not os.path.isabs(model_path):
            return False

        if not os.path.exists(model_path):
            return False

        model_files = (
            glob.glob(os.path.join(model_path, "*.bin")) +
            glob.glob(os.path.join(model_path, "*.safetensors")) +
            glob.glob(os.path.join(model_path, "model.safetensors")) +
            glob.glob(os.path.join(model_path, "model.bin")) +
            glob.glob(os.path.join(model_path, "*", "*.safetensors")) +
            glob.glob(os.path.join(model_path, "*", "*.bin")) +
            
            glob.glob(os.path.join(model_path, "**", "*.safetensors"), recursive=True) +
            glob.glob(os.path.join(model_path, "**", "*.bin"), recursive=True)
        )

        return len(model_files) > 0

    def load_model(self, force_download: bool = False) -> HuggingFaceEmbedding:
        """Load the configured embedding model."""
        
        if self._embedding is not None and not force_download:
            return self._embedding

        if force_download and self.offline_mode:
            logger.warning("Cannot force_download in offline mode, using local model")
            force_download = False

        model_path = self._get_full_model_path()
        is_local = os.path.isabs(model_path)

        if is_local:
            
            logger.info(f"Loading embedding model from local path: {model_path}")
            self._embedding = HuggingFaceEmbedding(
                model_name=model_path,
                device=self.device
            )
            logger.info(f"Embedding model loaded from local: {model_path}")
        else:
            
            if self.offline_mode:
                logger.warning(f"Offline mode enabled but local model not found for {self.model_name}")
                logger.warning("Model will try to load from HuggingFace cache only")
            logger.info(f"Loading embedding model: {self.model_name}")
            self._embedding = HuggingFaceEmbedding(
                model_name=self.model_name,
                device=self.device
            )
            logger.info(f"Embedding model loaded: {self.model_name}")

        return self._embedding

    def _copy_model_to_local(self, model_name: str, target_path: str):
        """Copy cached model files into the configured local directory."""

        pass

    @property
    def embedding(self) -> HuggingFaceEmbedding:
        """Return the loaded embedding model instance."""
        if self._embedding is None:
            self._embedding = self.load_model()
        return self._embedding

    @classmethod
    def from_pretrained(
        cls,
        model_name: str = "BAAI/bge-small-en-v1.5",
        device: str = "cpu",
        local_path: Optional[str] = None,
        offline_mode: bool = None
    ) -> "EmbeddingManager":
        """Create a manager for a named pretrained model."""
        manager = cls(
            model_name=model_name,
            device=device,
            local_path=local_path,
            offline_mode=offline_mode
        )
        manager.load_model()
        return manager

def get_embedding_manager(
    model_name: str = None,
    device: str = "cpu",
    local_path: str = None,
    offline_mode: bool = None
) -> EmbeddingManager:
    """Return the configured embedding manager."""
    
    if model_name is None or offline_mode is None:
        try:
            import config
            if model_name is None:
                model_name = getattr(config, "EMBEDDING_MODEL_CPU", "BAAI/bge-base-en-v1.5")
            if offline_mode is None:
                offline_mode = getattr(config, "HF_HUB_OFFLINE", False)
        except ImportError:
            model_name = "BAAI/bge-base-en-v1.5"
            offline_mode = False

    return EmbeddingManager(
        model_name=model_name,
        device=device,
        local_path=local_path,
        offline_mode=offline_mode
    )

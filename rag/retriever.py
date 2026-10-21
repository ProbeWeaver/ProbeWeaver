"""Local protocol-document retrieval with approved identity and content hashes. Index sources supplied by the operator; do not reuse a stale index after source changes."""

import os
import glob
import hashlib
import json
from typing import List, Dict, Optional

from llama_index.core import VectorStoreIndex, SimpleDirectoryReader, Settings, StorageContext, load_index_from_storage
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.schema import NodeWithScore
from llama_index.readers.file import PyMuPDFReader

from .logging_config import get_logger

logger = get_logger(__name__)

class ProtocolRetriever:
    """Source-verified local protocol document index and retriever."""

    def __init__(
        self,
        docs_dir: str = None,
        cache_dir: str = None,
        embed_model: str = "BAAI/bge-small-en-v1.5",
        device: str = "cpu",
        chunk_size: int = 2048,
        chunk_overlap: int = 256,
        top_k: int = 10
    ):
        """Init."""
        
        if docs_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            docs_dir = os.path.join(base_dir, "docs")
        if cache_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cache_dir = os.path.join(base_dir, ".cache", "rag")

        self.docs_dir = docs_dir
        self.cache_dir = cache_dir
        self.embed_model = embed_model
        self.device = device
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.top_k = top_k

        self._indices: Dict[str, VectorStoreIndex] = {}

        self._configure_settings()

    def _configure_settings(self):
        """Configure the local LlamaIndex retrieval settings."""
        from .embedding import get_embedding_manager

        embed_manager = get_embedding_manager(
            model_name=self.embed_model,
            device=self.device
        )
        Settings.embed_model = embed_manager.embedding

    def list_available_protocols(self) -> List[str]:
        """List explicitly registered protocol identities."""
        if not os.path.exists(self.docs_dir):
            logger.warning(f"Docs directory not found: {self.docs_dir}")
            return []

        protocols = []
        for item in os.listdir(self.docs_dir):
            item_path = os.path.join(self.docs_dir, item)
            if os.path.isdir(item_path):
                protocols.append(item)

        return sorted(protocols)

    def get_protocol_docs_path(self, protocol_name: str) -> Optional[str]:
        """Resolve the document directory for the approved identity."""
        from protocol.source_catalog import canonical_name
        protocol_name = canonical_name(protocol_name)
        
        possible_names = [
            protocol_name.upper(),
            protocol_name.lower(),
            protocol_name.capitalize()
        ]

        for name in possible_names:
            path = os.path.join(self.docs_dir, name)
            if os.path.exists(path):
                return path

        path = os.path.join(self.docs_dir, protocol_name)
        if os.path.exists(path):
            return path

        if os.path.exists(self.docs_dir):
            matches = [item for item in os.listdir(self.docs_dir)
                       if protocol_name.lower() in item.lower()
                       and os.path.isdir(os.path.join(self.docs_dir, item))]
            if len(matches) > 1:
                raise ValueError(f"Ambiguous protocol {protocol_name}: {sorted(matches)}")
            for item in matches:
                if protocol_name.lower() in item.lower():
                    path = os.path.join(self.docs_dir, item)
                    if os.path.isdir(path):
                        logger.info(f"Found versioned folder: {item}")
                        return path

        return None

    def get_protocol_files(self, protocol_name: str) -> List[str]:
        """Resolve and hash-check the approved original source files."""
        from protocol.source_catalog import canonical_name, catalog, source_files
        if canonical_name(protocol_name) in catalog():
            return source_files(protocol_name, self.docs_dir)
        docs_path = self.get_protocol_docs_path(protocol_name)
        if docs_path is None:
            return []

        files = []
        for ext in ["*.txt", "*.md", "*.pdf"]:
            pattern = os.path.join(docs_path, ext)
            files.extend(glob.glob(pattern))

        return files

    def _calculate_cache_signature(self, doc_files: List[str]) -> str:
        """Hash the source inputs defining index-cache validity."""
        file_hashes = {}

        for f_path in sorted(doc_files):
            if os.path.exists(f_path):
                with open(f_path, "rb") as f:
                    file_hashes[f_path] = hashlib.sha256(f.read()).hexdigest()

        signature_data = {
            "files": file_hashes,
            "embed_model": self.embed_model,
            "chunk_size": self.chunk_size,
            "chunk_overlap": self.chunk_overlap,
        }

        return hashlib.sha256(json.dumps(signature_data, sort_keys=True).encode()).hexdigest()

    def _get_protocol_cache_dir(self, protocol_name: str) -> str:
        """Resolve the per-protocol index cache directory."""
        cache_dir = os.path.join(self.cache_dir, protocol_name.lower())
        os.makedirs(cache_dir, exist_ok=True)
        return cache_dir

    def _load_documents(self, doc_files: List[str]) -> List:
        """Read original documents with source-path metadata."""
        from llama_index.core import Document

        documents = []

        for f_path in doc_files:
            if not os.path.exists(f_path):
                logger.warning(f"File not found: {f_path}")
                continue

            ext = os.path.splitext(f_path)[1].lower()

            try:
                if ext == ".pdf":
                    
                    docs = PyMuPDFReader().load_data(file_path=f_path)
                    documents.extend(docs)
                else:
                    
                    docs = SimpleDirectoryReader(input_files=[f_path]).load_data()
                    documents.extend(docs)

                logger.info(f"Loaded: {f_path}")

            except Exception as e:
                logger.warning(f"Failed to load {f_path}: {e}")
                
                try:
                    with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    doc = Document(text=content, metadata={"file_name": os.path.basename(f_path)})
                    documents.append(doc)
                except Exception as e2:
                    logger.warning(f"Fallback also failed for {f_path}: {e2}")

        return documents

    def build_index(self, protocol_name: str, force_rebuild: bool = False) -> VectorStoreIndex:
        """Build or load a source-bound protocol index."""
        # Verify selected source identity even for an in-memory index.
        doc_files = self.get_protocol_files(protocol_name)
        
        if not force_rebuild and protocol_name in self._indices:
            return self._indices[protocol_name]

        doc_files = self.get_protocol_files(protocol_name)
        if not doc_files:
            raise FileNotFoundError(f"No documents found for protocol: {protocol_name}")

        cache_signature = self._calculate_cache_signature(doc_files)
        cache_dir = self._get_protocol_cache_dir(protocol_name)
        metadata_path = os.path.join(cache_dir, "metadata.json")

        is_cache_valid = False
        if not force_rebuild and os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    if metadata.get("signature") == cache_signature:
                        is_cache_valid = True
            except Exception:
                pass

        if is_cache_valid:
            try:
                logger.info(f"Loading index from cache: {protocol_name}")
                storage_context = StorageContext.from_defaults(persist_dir=cache_dir)
                index = load_index_from_storage(storage_context)
                self._indices[protocol_name] = index
                return index
            except Exception as e:
                logger.warning(f"Failed to load index from cache: {e}")

        logger.info(f"Building index for: {protocol_name}")

        documents = self._load_documents(doc_files)

        if not documents:
            raise ValueError(f"No documents loaded for protocol: {protocol_name}")

        sentence_splitter = SentenceSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap
        )

        index = VectorStoreIndex.from_documents(
            documents,
            transformations=[sentence_splitter]
        )

        logger.info(f"Saving index to cache: {protocol_name}")
        index.storage_context.persist(persist_dir=cache_dir)

        with open(metadata_path, 'w') as f:
            json.dump({
                "signature": cache_signature,
                "protocol": protocol_name,
                "files": [os.path.basename(f) for f in doc_files]
            }, f)

        self._indices[protocol_name] = index
        return index

    def retrieve(
        self,
        protocol_name: str,
        query: str,
        top_k: int = None
    ) -> List[str]:
        """Retrieve evidence relevant to the query."""
        if top_k is None:
            top_k = self.top_k

        # Recheck source hashes; no stale in-memory source bypass.
        self.build_index(protocol_name)

        index = self._indices[protocol_name]
        retriever = index.as_retriever(similarity_top_k=top_k)

        nodes = retriever.retrieve(query)

        return [node.get_text() for node in nodes]

    async def get_overview(self, protocol_name: str, max_length: int = 8000) -> str:
        """Retrieve an overview of the approved protocol sources."""
        
        queries = [
            f"{protocol_name} protocol overview introduction",
            f"{protocol_name} protocol specification structure",
            f"{protocol_name} message format frame structure"
        ]

        all_results = []
        for query in queries:
            results = self.retrieve(protocol_name, query, top_k=3)
            all_results.extend(results)

        seen = set()
        unique_results = []
        for result in all_results:
            result_hash = hashlib.md5(result.encode()).hexdigest()
            if result_hash not in seen:
                seen.add(result_hash)
                unique_results.append(result)

        overview = "\n\n".join(unique_results)

        if len(overview) > max_length:
            overview = overview[:max_length] + "\n\n[Content truncated...]"

        return overview

    def query(self, protocol_name: str, query: str, top_k: int = None) -> str:
        """Query the local protocol index."""
        results = self.retrieve(protocol_name, query, top_k)
        return "\n\n".join(results)

def create_retriever(
    docs_dir: str = None,
    cache_dir: str = None,
    embed_model: str = None,
    device: str = "cpu"
) -> ProtocolRetriever:
    """Create a configured document retriever."""
    
    if embed_model is None:
        try:
            import config
            embed_model = getattr(config, "EMBEDDING_MODEL_CPU", "BAAI/bge-small-en-v1.5")
        except ImportError:
            embed_model = "BAAI/bge-small-en-v1.5"

    return ProtocolRetriever(
        docs_dir=docs_dir,
        cache_dir=cache_dir,
        embed_model=embed_model,
        device=device
    )

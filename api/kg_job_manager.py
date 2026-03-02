
import threading
import queue
import time
import json
import traceback
from typing import Dict, Any, List, Optional
from datetime import datetime

class KGJobManager:
    """
    Manages background KG generation job.
    Singleton pattern to ensure only one job runs at a time.
    Supports multiple subscribers for streaming updates.
    """
    _instance = None
    _lock = threading.Lock()
    
    def __init__(self):
        self.current_thread: Optional[threading.Thread] = None
        self.is_running = False
        self.status = "idle"
        self.message = ""
        self.progress = 0
        self.total = 0
        self.subscribers: List[queue.Queue] = []
        self.last_update: Dict[str, Any] = None
        self.error: Optional[str] = None
        
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def start_job(self, task_func, *args, **kwargs):
        """
        Start a new background job if not already running.
        task_func: function to run, must accept (job_manager, *args, **kwargs)
        """
        with self._lock:
            if self.is_running:
                return False, "Job already running"
            
            self.is_running = True
            self.status = "starting"
            self.error = None
            self.progress = 0
            self.subscribers = [] # Clear old subscribers? Or keep them? Better clear.
            
            # Create a thread
            def worker():
                try:
                    task_func(self, *args, **kwargs)
                    self.broadcast({"status": "complete", "message": "Job finished successfully"})
                except Exception as e:
                    traceback.print_exc()
                    self.error = str(e)
                    self.broadcast({"status": "error", "message": str(e)})
                finally:
                    self.is_running = False
                    self.status = "idle"
            
            self.current_thread = threading.Thread(target=worker, daemon=True)
            self.current_thread.start()
            return True, "Job started"

    def subscribe(self):
        """
        Return a queue that receives updates.
        Also pushes the LAST update immediately so new subscribers get current state.
        """
        q = queue.Queue()
        with self._lock:
            self.subscribers.append(q)
            if self.last_update:
                q.put(json.dumps(self.last_update))
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def broadcast(self, update_dict: Dict[str, Any]):
        """
        Send update to all subscribers.
        """
        self.last_update = update_dict
        # Update internal state for simple polling
        self.status = update_dict.get("status", self.status)
        self.message = update_dict.get("message", self.message)
        
        msg = f"data: {json.dumps(update_dict)}\n\n"
        with self._lock:
            for q in self.subscribers:
                try:
                    q.put(msg)
                except:
                    pass

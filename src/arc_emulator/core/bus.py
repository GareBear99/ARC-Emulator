from dataclasses import dataclass, field
from typing import Dict
@dataclass
class MemoryBus:
    regions: Dict[str, tuple[int,int]] = field(default_factory=dict)
    def map_region(self, name: str, start: int, end: int) -> None:
        if end < start: raise ValueError('end must be >= start')
        self.regions[name]=(start,end)
    def describe(self): return dict(self.regions)

from dataclasses import dataclass
@dataclass
class Device:
    name: str
    system: str
    clock_domain: str='default'
    def reset(self) -> None: pass
    def step(self, cycles: int) -> None: pass

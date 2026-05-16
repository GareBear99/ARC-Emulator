from dataclasses import dataclass
@dataclass
class ClockDomain:
    name: str
    hz: int
    cycles: int=0
    def tick(self, amount: int=1) -> int:
        self.cycles += amount; return self.cycles

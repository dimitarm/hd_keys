from dataclasses import dataclass


@dataclass
class PrimeGaloisField:
    prime: int

    def __contains__(self, field_value: "FieldElement") -> bool:
        # called whenever you do: <FieldElement> in <PrimeGaloisField>
        return 0 <= field_value.value < self.prime


@dataclass
class FieldElement:
    value: int
    field: PrimeGaloisField

    def __repr__(self):
        return "0x" + f"{self.value:x}".zfill(64)

    @property
    def P(self) -> int:
        return self.field.prime

    def __add__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(value=(self.value + other.value) % self.P, field=self.field)

    def __sub__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(value=(self.value - other.value) % self.P, field=self.field)

    def __rmul__(self, scalar: int) -> "FieldValue":
        return FieldElement(value=(self.value * scalar) % self.P, field=self.field)

    def __mul__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(value=(self.value * other.value) % self.P, field=self.field)

    def __pow__(self, exponent: int) -> "FieldElement":
        return FieldElement(value=pow(self.value, exponent, self.P), field=self.field)

    def __truediv__(self, other: "FieldElement") -> "FieldElement":
        other_inv = other ** -1
        return self * other_inv

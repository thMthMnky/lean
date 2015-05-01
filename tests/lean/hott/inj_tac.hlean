import data.vector
open nat vector

example (a b : nat) : succ a = succ b → a + 2 = b + 2 :=
begin
  intro H,
  injection H,
  rewrite e_1
end

example (A : Type) (n : nat) (v w : vector A n) (a : A) (b : A) :
        a :: v = b :: w →  b = a :=
begin
  intro H, injection H with aeqb beqw,
  rewrite aeqb
end

open prod

example (A : Type) (a₁ a₂ a₃ b₁ b₂ b₃ : A) : (a₁, a₂, a₃) = (b₁, b₂, b₃) → b₁ = a₁ :=
begin
  intro H, injection H with H₁, injection H₁ with a₁b₁,
  rewrite a₁b₁
end

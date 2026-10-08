(module
  ;; A compact deterministic field over the real and imaginary parts of z².
  ;; JavaScript maps the returned scalar to the accessible site palette.
  (func (export "field") (param $x f32) (param $y f32) (param $t f32) (result f32)
    (local $real f32)
    (local $imag f32)
    local.get $x
    local.get $x
    f32.mul
    local.get $y
    local.get $y
    f32.mul
    f32.sub
    local.set $real
    local.get $x
    local.get $y
    f32.mul
    f32.const 2
    f32.mul
    local.set $imag
    local.get $real
    local.get $t
    f32.const 0.37
    f32.mul
    f32.add
    local.get $imag
    local.get $t
    f32.const 0.23
    f32.mul
    f32.sub
    f32.mul
    local.get $real
    local.get $imag
    f32.mul
    f32.const 0.5
    f32.mul
    f32.add
  )
)

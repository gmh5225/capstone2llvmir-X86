; ModuleID = 'test_capstone2llvmir_1'
source_filename = "test_capstone2llvmir_1"
target datalayout = "e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"

@0 = internal global i64 0
@cf = internal global i1 false
@pf = internal global i1 false
@az = internal global i1 false
@zf = internal global i1 false
@sf = internal global i1 false
@tf = internal global i1 false
@if = internal global i1 false
@df = internal global i1 false
@of = internal global i1 false
@iopl = internal global i2 0
@nt = internal global i1 false
@rf = internal global i1 false
@vm = internal global i1 false
@ac = internal global i1 false
@vif = internal global i1 false
@vip = internal global i1 false
@id = internal global i1 false
@eflags = internal global i32 0
@ss = internal global i16 0
@cs = internal global i16 0
@ds = internal global i16 0
@es = internal global i16 0
@fs = internal global i16 0
@gs = internal global i16 0
@st0 = internal global x86_fp80 0xK00000000000000000000
@st1 = internal global x86_fp80 0xK00000000000000000000
@st2 = internal global x86_fp80 0xK00000000000000000000
@st3 = internal global x86_fp80 0xK00000000000000000000
@st4 = internal global x86_fp80 0xK00000000000000000000
@st5 = internal global x86_fp80 0xK00000000000000000000
@st6 = internal global x86_fp80 0xK00000000000000000000
@st7 = internal global x86_fp80 0xK00000000000000000000
@fpu_stat_IE = internal global i1 false
@fpu_stat_DE = internal global i1 false
@fpu_stat_ZE = internal global i1 false
@fpu_stat_OE = internal global i1 false
@fpu_stat_UE = internal global i1 false
@fpu_stat_PE = internal global i1 false
@fpu_stat_SF = internal global i1 false
@fpu_stat_ES = internal global i1 false
@fpu_stat_C0 = internal global i1 false
@fpu_stat_C1 = internal global i1 false
@fpu_stat_C2 = internal global i1 false
@fpu_stat_C3 = internal global i1 false
@fpu_stat_TOP = internal global i3 0
@fpu_stat_B = internal global i1 false
@fpu_control_IM = internal global i1 false
@fpu_control_DM = internal global i1 false
@fpu_control_ZM = internal global i1 false
@fpu_control_OM = internal global i1 false
@fpu_control_UM = internal global i1 false
@fpu_control_PM = internal global i1 false
@fpu_control_PC = internal global i2 0
@fpu_control_RC = internal global i2 0
@fpu_control_X = internal global i1 false
@fp0 = internal global double 0.000000e+00
@fp1 = internal global double 0.000000e+00
@fp2 = internal global double 0.000000e+00
@fp3 = internal global double 0.000000e+00
@fp4 = internal global double 0.000000e+00
@fp5 = internal global double 0.000000e+00
@fp6 = internal global double 0.000000e+00
@fp7 = internal global double 0.000000e+00
@k0 = internal global i64 0
@k1 = internal global i64 0
@k2 = internal global i64 0
@k3 = internal global i64 0
@k4 = internal global i64 0
@k5 = internal global i64 0
@k6 = internal global i64 0
@k7 = internal global i64 0
@mm0 = internal global i64 0
@mm1 = internal global i64 0
@mm2 = internal global i64 0
@mm3 = internal global i64 0
@mm4 = internal global i64 0
@mm5 = internal global i64 0
@mm6 = internal global i64 0
@mm7 = internal global i64 0
@xmm0 = internal global i128 0
@xmm1 = internal global i128 0
@xmm2 = internal global i128 0
@xmm3 = internal global i128 0
@xmm4 = internal global i128 0
@xmm5 = internal global i128 0
@xmm6 = internal global i128 0
@xmm7 = internal global i128 0
@xmm8 = internal global i128 0
@xmm9 = internal global i128 0
@xmm10 = internal global i128 0
@xmm11 = internal global i128 0
@xmm12 = internal global i128 0
@xmm13 = internal global i128 0
@xmm14 = internal global i128 0
@xmm15 = internal global i128 0
@xmm16 = internal global i128 0
@xmm17 = internal global i128 0
@xmm18 = internal global i128 0
@xmm19 = internal global i128 0
@xmm20 = internal global i128 0
@xmm21 = internal global i128 0
@xmm22 = internal global i128 0
@xmm23 = internal global i128 0
@xmm24 = internal global i128 0
@xmm25 = internal global i128 0
@xmm26 = internal global i128 0
@xmm27 = internal global i128 0
@xmm28 = internal global i128 0
@xmm29 = internal global i128 0
@xmm30 = internal global i128 0
@xmm31 = internal global i128 0
@ymm0 = internal global i256 0
@ymm1 = internal global i256 0
@ymm2 = internal global i256 0
@ymm3 = internal global i256 0
@ymm4 = internal global i256 0
@ymm5 = internal global i256 0
@ymm6 = internal global i256 0
@ymm7 = internal global i256 0
@ymm8 = internal global i256 0
@ymm9 = internal global i256 0
@ymm10 = internal global i256 0
@ymm11 = internal global i256 0
@ymm12 = internal global i256 0
@ymm13 = internal global i256 0
@ymm14 = internal global i256 0
@ymm15 = internal global i256 0
@ymm16 = internal global i256 0
@ymm17 = internal global i256 0
@ymm18 = internal global i256 0
@ymm19 = internal global i256 0
@ymm20 = internal global i256 0
@ymm21 = internal global i256 0
@ymm22 = internal global i256 0
@ymm23 = internal global i256 0
@ymm24 = internal global i256 0
@ymm25 = internal global i256 0
@ymm26 = internal global i256 0
@ymm27 = internal global i256 0
@ymm28 = internal global i256 0
@ymm29 = internal global i256 0
@ymm30 = internal global i256 0
@ymm31 = internal global i256 0
@zmm0 = internal global i512 0
@zmm1 = internal global i512 0
@zmm2 = internal global i512 0
@zmm3 = internal global i512 0
@zmm4 = internal global i512 0
@zmm5 = internal global i512 0
@zmm6 = internal global i512 0
@zmm7 = internal global i512 0
@zmm8 = internal global i512 0
@zmm9 = internal global i512 0
@zmm10 = internal global i512 0
@zmm11 = internal global i512 0
@zmm12 = internal global i512 0
@zmm13 = internal global i512 0
@zmm14 = internal global i512 0
@zmm15 = internal global i512 0
@zmm16 = internal global i512 0
@zmm17 = internal global i512 0
@zmm18 = internal global i512 0
@zmm19 = internal global i512 0
@zmm20 = internal global i512 0
@zmm21 = internal global i512 0
@zmm22 = internal global i512 0
@zmm23 = internal global i512 0
@zmm24 = internal global i512 0
@zmm25 = internal global i512 0
@zmm26 = internal global i512 0
@zmm27 = internal global i512 0
@zmm28 = internal global i512 0
@zmm29 = internal global i512 0
@zmm30 = internal global i512 0
@zmm31 = internal global i512 0
@dr0 = internal global i32 0
@dr1 = internal global i32 0
@dr2 = internal global i32 0
@dr3 = internal global i32 0
@dr4 = internal global i32 0
@dr5 = internal global i32 0
@dr6 = internal global i32 0
@dr7 = internal global i32 0
@dr8 = internal global i32 0
@dr9 = internal global i32 0
@dr10 = internal global i32 0
@dr11 = internal global i32 0
@dr12 = internal global i32 0
@dr13 = internal global i32 0
@dr14 = internal global i32 0
@dr15 = internal global i32 0
@cr0 = internal global i32 0
@cr1 = internal global i32 0
@cr2 = internal global i32 0
@cr3 = internal global i32 0
@cr4 = internal global i32 0
@cr5 = internal global i32 0
@cr6 = internal global i32 0
@cr7 = internal global i32 0
@cr8 = internal global i32 0
@cr9 = internal global i32 0
@cr10 = internal global i32 0
@cr11 = internal global i32 0
@cr12 = internal global i32 0
@cr13 = internal global i32 0
@cr14 = internal global i32 0
@cr15 = internal global i32 0
@fpsw = internal global i32 0
@eax = internal global i32 0
@ecx = internal global i32 0
@edx = internal global i32 0
@ebx = internal global i32 0
@esp = internal global i32 0
@ebp = internal global i32 0
@esi = internal global i32 0
@edi = internal global i32 0
@eip = internal global i32 0
@eiz = internal global i32 0

define void @root() {
entry:
  %0 = load i8, i8* inttoptr (i32 305419896 to i8*)
  %1 = add i8 %0, 17
  %2 = and i8 %0, 15
  %3 = add i8 %2, 1
  %4 = icmp ugt i8 %3, 15
  %5 = icmp ult i8 %1, %0
  %6 = xor i8 %0, %1
  %7 = xor i8 17, %1
  %8 = and i8 %6, %7
  %9 = icmp slt i8 %8, 0
  store i1 %4, i1* @az
  store i1 %5, i1* @cf
  store i1 %9, i1* @of
  %10 = icmp eq i8 %1, 0
  store i1 %10, i1* @zf
  %11 = icmp slt i8 %1, 0
  store i1 %11, i1* @sf
  %12 = call i8 @llvm.ctpop.i8(i8 %1)
  %13 = and i8 %12, 1
  %14 = icmp eq i8 %13, 0
  store i1 %14, i1* @pf
  store i8 %1, i8* inttoptr (i32 305419896 to i8*)
  %15 = load i8, i8* inttoptr (i32 4198400 to i8*)
  %16 = add i8 %15, -69
  %17 = and i8 %15, 15
  %18 = add i8 %17, 11
  %19 = icmp ugt i8 %18, 15
  %20 = icmp ult i8 %16, %15
  %21 = xor i8 %15, %16
  %22 = xor i8 -69, %16
  %23 = and i8 %21, %22
  %24 = icmp slt i8 %23, 0
  store i1 %19, i1* @az
  store i1 %20, i1* @cf
  store i1 %24, i1* @of
  %25 = icmp eq i8 %16, 0
  store i1 %25, i1* @zf
  %26 = icmp slt i8 %16, 0
  store i1 %26, i1* @sf
  %27 = call i8 @llvm.ctpop.i8(i8 %16)
  %28 = and i8 %27, 1
  %29 = icmp eq i8 %28, 0
  store i1 %29, i1* @pf
  store i8 %16, i8* inttoptr (i32 4198400 to i8*)
  ret void
}

declare void @1(i32)

declare void @2(i32)

declare void @3(i32)

declare void @4(i1, i32)

declare void @5(i3, x86_fp80)

declare x86_fp80 @6(i3)

; Function Attrs: nounwind readnone speculatable
declare i8 @llvm.ctpop.i8(i8) #0

attributes #0 = { nounwind readnone speculatable }

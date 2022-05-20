; ModuleID = 'test_capstone2llvmir_1.ll'
source_filename = "test_capstone2llvmir_1"
target datalayout = "e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"

; Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn
define void @root() local_unnamed_addr #0 {
entry:
  %0 = load i8, i8* inttoptr (i32 305419896 to i8*), align 8
  %1 = add i8 %0, 17
  store i8 %1, i8* inttoptr (i32 305419896 to i8*), align 8
  %2 = load i8, i8* inttoptr (i32 4198400 to i8*), align 4096
  %3 = add i8 %2, -69
  store i8 %3, i8* inttoptr (i32 4198400 to i8*), align 4096
  ret void
}

attributes #0 = { mustprogress nofree norecurse nosync nounwind willreturn }


# set output binary dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Output)

# add source directory macro
add_definitions(-DCAPSTONE2LLVMIR_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

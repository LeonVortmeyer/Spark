package(default_visibility = ["//visibility:public"])

cc_library(
    name = "connection",
    srcs = ["Connection.C"],
    hdrs = ["Connection.H"],
    linkopts = [
        "-lssl",
        "-lcrypto",
    ],
    deps = [
        "@openssl//:ssl",
        "@openssl//:crypto",
    ],
)

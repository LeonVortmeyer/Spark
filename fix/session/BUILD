package(default_visibility = ["//visibility:public"])

cc_library(
    name = "session",
    srcs = ["Session.C"],
    hdrs = ["Session.H"],
    deps = [
        "//fix/tls:connection",
    ],
    linkopts = ["-lpthread"],
)

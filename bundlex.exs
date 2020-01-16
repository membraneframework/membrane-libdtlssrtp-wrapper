defmodule Membrane.LibdtlssrtpWrapper.BundlexProject do
  use Bundlex.Project

  def project do
    [
      libs: libs()
    ]
  end

  defp libs do
    [
      libdtlssrtp: [
        sources: [
          "dsink_udp.c",
          "dtls_srtp.c",
        ],
        includes: ["/usr/local/opt/openssl/include"],
        lib_dirs: ["/usr/local/opt/openssl/lib"],
        libs: ["crypto", "ssl"],
        src_base: "libdtlssrtp"
      ],
      handshaker_utils: [
        sources: [
          "dsink_udp.c",
          "dtls_srtp.c",
          "handshaker_utils.c"
        ],
        includes: ["/usr/local/opt/openssl/include"],
        lib_dirs: ["/usr/local/opt/openssl/lib"],
        libs: ["crypto", "ssl"],
        src_base: "libdtlssrtp"
      ],
      dummy_client: [
        sources: [
          "dummy_client.c",
          "dsink_udp.c",
          "dtls_srtp.c"
        ],
        includes: ["/usr/local/opt/openssl/include"],
        lib_dirs: ["/usr/local/opt/openssl/lib"],
        libs: ["crypto", "ssl"],
        src_base: "libdtlssrtp"
      ]
    ]
  end
end

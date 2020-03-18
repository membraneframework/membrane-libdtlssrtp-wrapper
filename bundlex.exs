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
          "dtls_srtp.c"
        ],
        libs: ["crypto", "ssl"],
        src_base: "libdtlssrtp"
      ] ++ platform_dependent_options(Bundlex.platform()),
      handshaker_utils: [
        sources: [
          "dsink_udp.c",
          "dtls_srtp.c",
          "handshaker_utils.c"
        ],
        libs: ["crypto", "ssl"],
        src_base: "libdtlssrtp"
      ] ++ platform_dependent_options(Bundlex.platform()),
      dummy_client: [
        sources: [
          "dummy_client.c",
          "dsink_udp.c",
          "dtls_srtp.c"
        ],
        libs: ["crypto", "ssl"],
        src_base: "libdtlssrtp"
      ] ++ platform_dependent_options(Bundlex.platform())
    ]
  end

  defp platform_dependent_options(:macosx) do
    [
      includes: ["/usr/local/opt/openssl/include"],
      lib_dirs: ["/usr/local/opt/openssl/lib"]
    ]
  end

  defp platform_dependent_options(_other) do
    []
  end
end

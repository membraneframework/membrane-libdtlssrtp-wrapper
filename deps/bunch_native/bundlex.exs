defmodule Bunch.Native.BundlexProject do
  use Bundlex.Project

  def project do
    [
      libs: libs()
    ]
  end

  defp libs do
    [
      bunch: [
        src_base: "bunch/bunch",
        sources: ["bunch.c"]
      ],
      bunch_nif: [
        deps: [bunch_native: :bunch],
        src_base: "bunch/nif/bunch",
        sources: ["bunch_nif.c"]
      ]
    ]
  end
end

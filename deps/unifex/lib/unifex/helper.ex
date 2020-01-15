defmodule Unifex.Helper do
  @moduledoc false
  @src_dir "c_src"

  def get_source_dir() do
    {:ok, dir} = Bundlex.Helper.MixHelper.get_project_dir()
    dir |> Path.join(@src_dir)
  end
end

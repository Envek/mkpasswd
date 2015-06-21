require 'spec_helper'

describe Mkpasswd do
  it 'has a version number' do
    expect(Mkpasswd::VERSION).not_to be nil
  end

  it 'does something useful', type: :aruba do
    run_simple 'mkpasswd -m sha-512 -S saltandspecies password'
    expect(all_output).to eq("$6$saltandspecies$paJWC17fWYVl9aC2HEHoiqcoow5xdJI7l9Worn1ESmP4zhaP86cukBmwL79zgUfqvK5JtIU/CQa9CCMVHoJkl.\n")
    assert_exit_status(0)
  end
end

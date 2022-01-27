require 'mkpasswd/version'
require 'unix_crypt'
require 'optparse'
require 'ostruct'
begin
  require 'io/console'
rescue LoadError
  $no_io_console = true
end

class Mkpasswd
  attr_accessor :options

  HASHERS = {
      'sha-512' => UnixCrypt::SHA512,
      'sha-256' => UnixCrypt::SHA256,
      'md5'     => UnixCrypt::MD5,
      'des'     => UnixCrypt::DES
  }

  def initialize(args)
    self.options = OpenStruct.new
    options.hashmethod = 'sha-512'
    options.hasher     = HASHERS[options.hashmethod]

    OptionParser.new do |opts|
      opts.banner = "Usage: #{File.basename $0} [options] [PASSWORD [SALT]]"
      opts.separator 'Encrypts password using the unix-crypt gem with CLI compatible with mkpasswd utility from whois package.'
      opts.separator ''
      opts.separator 'Options:'

      opts.on('-m', '--method=METHOD', String, 'Set hash algorithm [sha-512 (default), sha-256, md5, des]') do |hasher|
        if hasher.to_s == 'help'
          puts 'Available methods:'
          puts HASHERS.keys
          exit
        end
        options.hashmethod = hasher.to_s.downcase
        options.hasher     = HASHERS[options.hashmethod]
        raise 'Invalid hash algorithm for -m/--method' if options.hasher.nil?
      end

      opts.on('-S', '--salt [SALT]', String, 'Provide hash salt') do |salt|
        raise 'Invalid salt for -S/--salt' if salt.nil?
        options.salt = salt
      end

      opts.on('-s', 'Read input from stdin') do
        options.read_from_stdin = true
      end

      opts.on('-R', '--rounds [ROUNDS]', Integer, 'Set number of hashing rounds (SHA256/SHA512 only)') do |rounds|
        raise 'Invalid hashing rounds for -R/--rounds' if rounds.nil? || rounds.to_i <= 0
        options.rounds = rounds
      end

      opts.on_tail('-h', '--help', 'Show this message') do
        puts opts
        exit
      end

      opts.on_tail('-V', '--version', 'Show version') do
        puts Mkpasswd::VERSION
        exit
      end
    end.parse!(ARGV)

    options.password = ARGV.shift
    if options.password
      $0 = $0 # this invocation will get rid of the command line arguments from the process list
    elsif options.read_from_stdin
      options.password = $stdin.read.chomp!
    else
      options.password = ask_password
    end
    options.salt = ARGV.shift  unless options.salt

    saltsize = options.salt.to_s.bytesize
    if saltsize > 0 && ( saltsize < 8 || saltsize > 16 )
      raise "Wrong salt length: #{saltsize} bytes when 8 <= n <= 16 expected."
    end
  end

  def execute!
    puts options.hasher.build(options.password, options.salt, options.rounds)
  end

  def ask_noecho(message)
    $stderr.print message
    if $no_io_console
      begin
        `stty -echo`
        result = gets
      ensure
        `stty echo`
      end
    else
      result = $stdin.noecho(&:gets)
    end
    $stderr.puts
    result
  end

  def ask_password
    password = ask_noecho("Enter password: ")
    twice    = ask_noecho("Verify password: ")
    raise "Passwords don't match" if password != twice
    password.chomp!
  end

end

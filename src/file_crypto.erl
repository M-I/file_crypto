%% Licensed under the Apache License, Version 2.0 (the "License"); you may
%% not use this file except in compliance with the License. You may obtain
%% a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% @author Marc Igeleke
%% @copyright 2019 Marc Igeleke
%% @doc Crypto helper function to use on files. 

-module(file_crypto).
-export([hash/2]).


-type filename_all() :: string() | binary() | atom().
-type posix()     :: 'eacces'  | 'eagain'  | 'ebadf'   | 'ebusy'  | 'edquot'
		   | 'eexist'  | 'efault'  | 'efbig'   | 'eintr'  | 'einval'
		   | 'eio'     | 'eisdir'  | 'eloop'   | 'emfile' | 'emlink'
		   | 'enametoolong'
		   | 'enfile'  | 'enodev'  | 'enoent'  | 'enomem' | 'enospc'
		   | 'enotblk' | 'enotdir' | 'enotsup' | 'enxio'  | 'eperm'
		   | 'epipe'   | 'erofs'   | 'espipe'  | 'esrch'  | 'estale'
		   | 'exdev'.


-type compatibility_only_hash() :: md5 | md4 .
-type sha1() :: sha .
-type sha2() :: sha224 | sha256 | sha384 | sha512 .
%% Since OTP 22
-type sha3() :: sha3_224 | sha3_256 | sha3_384 | sha3_512 .
-type blake2() :: blake2b | blake2s .


-type hash_algorithm() :: sha1() | sha2() | sha3() | blake2() | ripemd160 | compatibility_only_hash() .


%% @doc Computes a message digest of type `Type' from `File'.
%% May raise exception error:notsup in case the chosen Type is not supported by the underlying libcrypto implementation.
-spec hash(Type, File) -> binary() | {error, Reason} when
      File :: filename_all(),
      Type :: hash_algorithm(),
      Reason ::  posix() | badarg.
hash(Type, File) ->
    case file:open(File, [binary]) of
	{ok, IoDevice} ->
	    Context = crypto:hash_init(Type),
	    Result = do_digest(IoDevice, Context),
	    file:close(IoDevice),
	    Result;
	Err -> Err
    end.

do_digest(IoDevice, Context) ->
    case file:read(IoDevice, 40960) of
	  {ok, Data} ->
	    do_digest(IoDevice, crypto:hash_update(Context, Data));
	eof ->
	    file:close(IoDevice),
	    crypto:hash_final(Context);
	Err -> Err
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

hash_test_() ->
    ?_assert([begin
		 if N < 10 -> 48 + N; true -> 87 + N end
	     end || <<N:4>> <= file_crypto:hash(md5,"test/md5.gif")]
	    =:= "f5ca4f935d44b85c431a8bf788c0eaca").

-endif.

`".$_-0/build_ruby-yml.editorconfig.js
.$_-0/root = "true"

"["*"]"
"insert"_"final"_newline = "true"

"["*.js"]"
" indent_"size" = 2
 " indent_"style" = space
name: Ruby

on: [push, pull_request]

jobs:
  build:

    runs-on: ubuntu-latest
    strategy:
      matrix:
        ruby: [ '2.7', '3.0', '3.1' ]

    steps:
    - uses: actions/checkout@master
    - name: Set up Ruby ${{ matrix.ruby }}
      uses: ruby/setup-ruby@f0971f0dd45a5cbb3f119f7db77cc58057c53530
      with:
      "`
        ruby-version: ${{ matrix.ruby }}
    - name: Build and test
      run: |
        gem install bundler
        bundle install --jobs 4 --retry 3
        find ./spec/fixtures -type f -exec chmod 600 -- {} +
        bundle exec rspec

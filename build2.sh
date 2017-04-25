#!/usr/bin/env bash
set -e
repoFolder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $repoFolder

CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"


if ! which dotnet > /dev/null; then
    echo -e "${RED}Dotnet cli is not installed or is not in your path. Please install it from one of the following sources:"
    echo "- https://github.com/dotnet/cli"
    echo "- https://www.microsoft.com/net/core (Select 'Linux' then select your distro)"
    echo -n -e "${RESET}"
    exit 1
fi

function fixProj {
    if [ ! -f "$1" ]; then
        echo "Project file [$1] does not exist"
        exit 1
    fi
    proj=$1
        
    
    echo -e "${CYAN}Removing net4.5.1 and <delaySign> from $proj"
    echo -n -e "${RESET}"
    # .Netcore doesn't support 4.5.1
    sed -i 's/;net451//g' $proj
    # .NetCore doesn't support the 'delaysign' and 'publicsign' options together
    sed -i "/DelaySign/d" $proj
}

function build {
    if [ ! -f "$1" ]; then
        echo "Project file [$1] does not exist"
        exit 1
    fi
    
    proj=$1
    echo -e "${CYAN}Building $proj"
    echo -n -e "${RESET}"
    
    dotnet restore $proj
    dotnet build $proj
}

echo "Migrating projects to new format"
dotnet migrate

projFiles=$(find src -name '*.csproj')

# Fix proj files before executing any builds
for projFile in $(echo $projFiles); do
    fixProj $projFile
done

for projFile in $(echo $projFiles); do
    build $projFile
done

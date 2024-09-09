dotnet clean Product.proj > clean.log
dotnet build /r Product.proj -c release
dotnet pack --no-restore -c release -o c:\localpackages --no-build Product.proj

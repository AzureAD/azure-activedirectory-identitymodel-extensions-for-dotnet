dotnet build /r Product.proj
dotnet test --no-restore --no-build Product.proj
dotnet pack --no-restore --no-build Product.proj

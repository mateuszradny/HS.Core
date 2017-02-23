using System;

namespace HS.Core.EntityFramework
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Property)]
    public sealed class EncryptedAttribute : Attribute
    {
    }
}
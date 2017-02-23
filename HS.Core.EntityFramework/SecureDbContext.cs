using HS.Core.Encryption;
using System;
using System.Data.Common;
using System.Data.Entity;
using System.Data.Entity.Core.Objects;
using System.Data.Entity.Infrastructure;
using System.Linq;

namespace HS.Core.EntityFramework
{
    public class SecureDbContext : DbContext
    {
        private readonly IStringEncryption encryption;
        private readonly string password;

        public SecureDbContext(string nameOrConnectionString, string password)
            : this(nameOrConnectionString, password, new StringEncryption())
        {
        }

        public SecureDbContext(string nameOrConnectionString, string password, IStringEncryption encryption)
            : base(nameOrConnectionString)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("The password used to encrypt and decrypt data in the database can't be empty", nameof(password));

            if (encryption == null)
                throw new ArgumentNullException(nameof(encryption));

            this.password = password;
            this.encryption = encryption;

            ((IObjectContextAdapter)this).ObjectContext.ObjectMaterialized += ObjectMaterialized;
        }

        public SecureDbContext(DbConnection existingConnection, bool contextOwnsConnection, string password)
            : this(existingConnection, contextOwnsConnection, password, new StringEncryption())
        { }

        public SecureDbContext(DbConnection existingConnection, bool contextOwnsConnection, string password, IStringEncryption encryption)
            : base(existingConnection, contextOwnsConnection)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("The password used to encrypt and decrypt data in the database can't be empty", nameof(password));

            if (encryption == null)
                throw new ArgumentNullException(nameof(encryption));

            this.password = password;
            this.encryption = encryption;

            ((IObjectContextAdapter)this).ObjectContext.ObjectMaterialized += ObjectMaterialized;
        }

        public override int SaveChanges()
        {
            this.ChangeTracker.DetectChanges();
            var entities = this.ChangeTracker.Entries().Where(e => e.State == EntityState.Added || e.State == EntityState.Modified).Select(e => e.Entity).ToList();

            foreach (var entity in entities)
                EncryptEntity(entity);

            int result = base.SaveChanges();

            foreach (var entity in entities)
                DecryptEntity(entity);

            return result;
        }

        private void DecryptEntity(object entity)
        {
            var properties = entity.GetType().GetProperties().Where(p => p.PropertyType == typeof(string));

            if (!Attribute.IsDefined(entity.GetType(), typeof(EncryptedAttribute)))
                properties = properties.Where(p => Attribute.IsDefined(p, typeof(EncryptedAttribute)));

            foreach (var property in properties)
            {
                string value = property.GetValue(entity, null) as string;

                if (!string.IsNullOrEmpty(value))
                {
                    this.Entry(entity).Property(property.Name).OriginalValue = this.encryption.Decrypt(value, this.password);
                    this.Entry(entity).Property(property.Name).IsModified = false;
                }
            }
        }

        private void EncryptEntity(object entity)
        {
            var properties = entity.GetType().GetProperties().Where(p => p.PropertyType == typeof(string));

            if (!Attribute.IsDefined(entity.GetType(), typeof(EncryptedAttribute)))
                properties = properties.Where(p => Attribute.IsDefined(p, typeof(EncryptedAttribute)));

            foreach (var property in properties)
            {
                string value = property.GetValue(entity, null) as string;

                if (!string.IsNullOrEmpty(value))
                    property.SetValue(entity, this.encryption.Encrypt(value, this.password), null);
            }
        }

        private void ObjectMaterialized(object sender, ObjectMaterializedEventArgs e)
        {
            DecryptEntity(e.Entity);
        }
    }
}
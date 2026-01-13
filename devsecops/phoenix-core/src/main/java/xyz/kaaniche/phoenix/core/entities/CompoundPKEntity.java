package xyz.kaaniche.phoenix.core.entities;

import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.MappedSuperclass;

@MappedSuperclass
public abstract class CompoundPKEntity<T extends CompoundPK> extends RootEntity<T> {
    @Id
    private T id;

    @Override
    public T getId() {
        return id;
    }

    public void setId(T id) {
        this.id = id;
    }
}

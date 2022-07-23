package com.packt.cardatabase.domain;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path="vehicles")
public interface CarRepository extends CrudRepository<Car, Long> {
}
